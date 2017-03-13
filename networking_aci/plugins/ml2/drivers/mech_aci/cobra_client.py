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
import requests

from oslo_log import log

from cobra.mit.access import MoDirectory
from cobra.mit.session import LoginSession
from cobra.mit.request import ConfigRequest
from cobra.mit.request import ConfigRequest
from cobra.mit.request import CommitError
from cobra.mit.request import QueryError
from cobra.mit.request import DnQuery
from requests.exceptions import SSLError
from cobra.model.fv import Tenant

LOG = log.getLogger(__name__)

RETRY_LIMIT = 2

requests.packages.urllib3.disable_warnings()

class CobraClient(object):
    def __init__(self, hosts, user, password, ssl, verify=False, request_timeout=90):
        protocol = 'https' if ssl else 'http'


        LOG.info(hosts)

        self.api_base = collections.deque(['%s://%s/api' % (protocol, host) for host in hosts])
        self.verify = verify
        self.timeout = 90
        self.user = user
        self.password = password
        self.login()

    def login(self):
        # TODO handle multiple hosts
        LOG.info("ACI Login")
        login_session = LoginSession(self.api_base[0], self.user, self.password)
        self.mo_dir = MoDirectory(login_session)
        self.mo_dir.login()

        LOG.info("Login session created, will expire at {} in {} seconds".format(login_session.refreshTime,login_session.refreshTimeoutSeconds))


    def logout(self):
        self.mo_dir.logout()

    def lookupByDn(self, dn):
        retries = 0
        while retries < RETRY_LIMIT:
            try:
                uni_mo = self.mo_dir.lookupByDn(dn)
                return uni_mo
            except SSLError as e:
                self._retry(retries, e)
            except QueryError  as e:
                LOG.info("Lookup to ACI failed due to {}:{} retrying {} of {}".format(e.error, e.reason,retries,RETRY_LIMIT))
                if e.error == 403:
                    self.mo_dir.login()
                    LOG.info("New login session created")
                    self._retry(retries, e)
                else:
                    raise e

    def commit(self, managed_objects):
        retries = 0
        while retries < RETRY_LIMIT:
            try:
                config_request = ConfigRequest()

                if isinstance(managed_objects, list):
                    for mos in managed_objects:
                        config_request.addMo(mos)
                else:
                    config_request.addMo(managed_objects)

                return self.mo_dir.commit(config_request)
            except SSLError as e:
                self._retry(retries, e)
            except CommitError  as e:
                LOG.info("Commit to ACI failed due to {}:{} retrying  {} of {}".format(e.error, e.reason, retries,RETRY_LIMIT))
                if e.error == 403:
                    self.mo_dir.login()
                    LOG.info("New login session created")
                    self._retry(retries, e)
                else:
                    raise e

    def _retry(self, retries, e):
        retries += 1
        if retries >= RETRY_LIMIT:
            raise e

    def mo_exists(self, dn):
        mo = self.lookupByDn(dn)
        return mo is not None

    def uni_mo(self):
        return self.lookupByDn('uni')

    def get_full_tenant(self,tenant_name):
        dnQ = DnQuery('uni/tn-{}'.format(tenant_name))
        dnQ.subtree = 'full'
        tenant = self.mo_dir.query(dnQ)

        if tenant:
            return tenant[0]

        return None

    def get_tenant(self,tenant_name):
        tenant_mo = Tenant(self.uni_mo(), tenant_name)
        if self.mo_exists(tenant_mo.dn):
            return tenant_mo

        return None

    def get_or_create_tenant(self, tenant_name):
        tenant_mo = Tenant(self.uni_mo(), tenant_name)

        if not self.mo_exists(tenant_mo.dn):
            LOG.debug("Configured tenant {} is missing, creating it now".format(tenant_mo.dn))
            self.commit(tenant_mo)
        else:
            LOG.debug("Using existing ACI tenant {}".format(tenant_mo.dn))

        return tenant_mo