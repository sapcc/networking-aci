# Copyright 2016 SAP SE
# All Rights Reserved.
#
#    Licensed under the Apache License, Version 2.0 (the "License"); you may
#    not use this file except in compliance with the License. You may obtain
#    a copy of the License at
#
#         http://www.apache.org/licenses/LICENSE-2.0
#
#    Unless required by applicable law or agreed to in writing, software
#    distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
#    WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
#    License for the specific language governing permissions and limitations
#    under the License.
import collections
import functools
import threading
import time

from cobra.mit.access import MoDirectory
from cobra.mit.request import CommitError
from cobra.mit.request import ConfigRequest
from cobra.mit.request import DnQuery
from cobra.mit.session import LoginSession, LoginError
from cobra.mit.request import QueryError
from cobra.model.fv import Tenant
from oslo_config import cfg
from oslo_log import log
import requests
import requests.exceptions as rexc
from requests.exceptions import SSLError

LOG = log.getLogger(__name__)
CONF = cfg.CONF

RETRY_LIMIT = 2
FALLBACK_EXCEPTIONS = (rexc.ConnectionError, rexc.Timeout,
                       rexc.TooManyRedirects, rexc.InvalidURL,
                       rexc.HTTPError, LoginError)
RETRY_EXCEPTIONS = FALLBACK_EXCEPTIONS + (SSLError, CommitError, QueryError)
requests.packages.urllib3.disable_warnings()
_TOKEN_REFRESH_LOCK = threading.Lock()


def _retry(func):
    @functools.wraps(func)
    def wrapper(self, *args, **kwargs):
        retry = kwargs.pop("retry", 0)
        max_retries = kwargs.pop("max_retries", 3)

        try:
            # check if token is still valid
            token_validity = (self.mo_dir.session.refreshTime or 0) - time.time()
            if token_validity < CONF.ml2_aci.reauth_threshold:
                LOG.debug("Acquiring session refresh lock")
                with _TOKEN_REFRESH_LOCK:
                    if token_validity >= CONF.ml2_aci.reauth_threshold:
                        LOG.debug("Session was already refreshed by another thread, continuing")
                    elif token_validity > 1:
                        LOG.debug("Session only valid for %ss, refreshing auth", token_validity)
                        self.mo_dir.reauth()
                    else:
                        LOG.info("Session timed out (%ss), triggering relogin", token_validity)
                        self.login()
                LOG.debug("Releasing session refresh lock")

            return func(self, *args, **kwargs)
        except RETRY_EXCEPTIONS as e:
            msg = ("Try {}/{}: Call to {}() failed due to {}: {}"
                   .format(retry, max_retries, func.__name__, e.__class__.__name__, e))

            trigger_login = True
            if isinstance(e, (CommitError, QueryError)):
                if isinstance(e, CommitError) and e.error == 102:
                    LOG.warning("%s - sleeping and retrying to avoid race condition", e.reason)
                    trigger_login = False
                    time.sleep(1)
                elif e.error == 403:
                    # relogin on error 403
                    pass
                else:
                    # reraise
                    LOG.exception("Commit failed")
                    raise

            if retry < max_retries:
                if trigger_login:
                    LOG.info("%s - calling login()", msg)
                    LOG.debug("Acquiring session refresh lock for login")
                    with _TOKEN_REFRESH_LOCK:
                        self.login()
                    LOG.debug("Releasing session refresh lock for login")

                return wrapper(self, *args, retry=retry + 1, max_retries=max_retries, **kwargs)
            else:
                LOG.exception("%s", msg)
                raise
    return wrapper


class CobraClient(object):
    def __init__(self, hosts, user, password, ssl, verify=False, request_timeout=90):
        LOG.info(hosts)

        protocol = 'https' if ssl else 'http'
        self.api_base = collections.deque(['%s://%s/api' % (protocol, host) for host in hosts])
        self.verify = verify
        self.timeout = 90
        self.user = user
        self.password = password
        self.login()

    def login(self):
        # NOTE: login() is called by _retry(). To avoid deadlocks it should not call any methods that trigger a _retry()

        for x in range(len(self.api_base)):
            try:
                LOG.info("ACI Login: Logging into %s as user %s", self.api_base[0], self.user)
                login_session = LoginSession(self.api_base[0], self.user, self.password)
                self.mo_dir = MoDirectory(login_session)
                self.mo_dir.login()

                LOG.info("Login session created, will expire at {} in {} seconds"
                         .format(login_session.refreshTime, login_session.refreshTimeoutSeconds))
                break
            except FALLBACK_EXCEPTIONS as exc:
                LOG.info('%s, falling back to a new address', exc.message)
                self.api_base.rotate(-1)
                LOG.info('New controller address: %s ', self.api_base[0])

    def logout(self):
        self.mo_dir.logout()

    @_retry
    def commit(self, managed_objects):
        config_request = ConfigRequest()

        if isinstance(managed_objects, list):
            for mos in managed_objects:
                config_request.addMo(mos)
        else:
            config_request.addMo(managed_objects)

        return self.mo_dir.commit(config_request)

    @_retry
    def lookupByDn(self, dn, **kwargs):
        """Simple wrapper for cobra lookupByDn with retry"""
        return self.mo_dir.lookupByDn(dn, **kwargs)

    @_retry
    def lookupByClass(self, dn, **kwargs):
        """Simple wrapper for cobra lookupByClass with retry"""
        return self.mo_dir.lookupByClass(dn, **kwargs)

    @_retry
    def query(self, dn, single=False, **kwargs):
        dnQ = DnQuery(dn)
        # allow passing a list for certain attributes
        for item in ('subtreeClassFilter',):
            if isinstance(kwargs.get(item), (tuple, list)):
                kwargs[item] = ",".join(kwargs[item])

        # set all query parameters, similar to DnQuery.__setQueryParams
        for param, value in list(kwargs.items()):
            if value is not None:
                setattr(dnQ, param, value)

        result = self.mo_dir.query(dnQ)
        if single:
            if len(result) > 1:
                raise ValueError("Expected single entry for dn query for {}, found {}".format(dn, len(result)))
            if not result:
                return None
            return result[0]
        return result

    def mo_exists(self, dn):
        mo = self.lookupByDn(dn)
        return mo is not None

    def uni_mo(self):
        return 'uni'

    def get_full_tenant(self, tenant_name):
        return self.query("uni/tn-{}".format(tenant_name), subtree="full", single=True)

    def get_tenant(self, tenant_name):
        tenant_mo = Tenant(self.uni_mo(), tenant_name)
        if self.mo_exists(tenant_mo.dn):
            return tenant_mo

        return None

    def get_bd(self, tenant_name, network_id, children=('fvSubnet',)):
        dn = "uni/tn-{}/BD-{}".format(tenant_name, network_id)
        return self.query(dn, subtree="full", subtreeClassFilter=children, single=True)

    def get_epg(self, tenant_name, app_profile, network_id, children=('fvRsPathAtt', 'fvRsDomAtt')):
        dn = "uni/tn-{}/ap-{}/epg-{}".format(tenant_name, app_profile, network_id)
        return self.query(dn, subtree="full", subtreeClassFilter=children, single=True)

    def get_or_create_tenant(self, tenant_name):
        tenant_mo = Tenant(self.uni_mo(), tenant_name)

        if not self.mo_exists(tenant_mo.dn):
            LOG.debug("Configured tenant {} is missing, creating it now".format(tenant_mo.dn))
            self.commit(tenant_mo)
        else:
            LOG.debug("Using existing ACI tenant {}".format(tenant_mo.dn))

        return tenant_mo
