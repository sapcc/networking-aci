openstack-networking-aci
========================

Openstack L2 networking components using hierarchical port binding with an ACI overlay network

Install on devstack
-------------------

Download & Install and setup the Cobra ACI SDK for python

https://[apic ip/fqdn]/cobra/install.html

clone repo into /opt/stack

cd ./networking-aci

python setup.py install

neutron-db-manage --subproject networking-aci upgrade head

check and modify /etc/neutron/plugins/ml2/ml2_conf_cisco.ini

add aci mechanism driver to /etc/neutron/plugins/ml2/ml2_conf.ini

restart neutron server with aci ml2 config

/usr/local/bin/neutron-server --config-file /etc/neutron/neutron.conf --config-file /etc/neutron/plugins/ml2/ml2_conf.ini --config-file /etc/neutron/plugins/ml2/ml2_conf_aci.ini

