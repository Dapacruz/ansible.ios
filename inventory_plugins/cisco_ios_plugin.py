#!/usr/bin/env python3

from __future__ import absolute_import, division, print_function

__metaclass__ = type

import os
import re

import requests
from ansible.errors import AnsibleError, AnsibleParserError
from ansible.plugins.inventory import BaseInventoryPlugin

DOCUMENTATION = r"""
    name: cisco_ios_plugin
    plugin_type: inventory
    short_description: Returns Ansible inventory from NetBrain
    description: Returns Ansible inventory from NetBrain
    options:
      plugin:
          description: Get Cisco routers from NetBrain
          required: True
          choices: ['cisco_ios_plugin']
"""


class InventoryModule(BaseInventoryPlugin):
    NAME = "cisco_ios_plugin"

    def verify_file(self, path):
        """return True/False if this is possibly a valid file for this plugin to consume"""
        if super(InventoryModule, self).verify_file(path):
            # base class verifies that file exists and is readable by current user
            if path.endswith(("cisco_ios_inventory.yaml", "cisco_ios_inventory.yml")):
                return True
        return False

    def _get_structured_inventory(self, device_group):
        nb = NetBrain(
            self.netbrain_url,
            self.netbrain_username,
            self.netbrain_password,
            verify=False,
        )
        tenant_id = next(
            dict["tenantId"]
            for dict in nb.get_tenants()
            if dict["tenantName"] == self.netbrain_tenant_name
        )
        domain_id = next(
            dict["domainId"]
            for dict in nb.get_domains(tenant_id)
            if dict["domainName"] == self.netbrain_domain_name
        )
        nb.set_current_domain(tenant_id, domain_id)

        # Get device names
        device_names = [
            attrs["hostname"] for attrs in nb.get_group_devices(device_group)
        ]

        # Get device attributes
        devices = list()
        for device in sorted(device_names):
            devices.append(nb.get_device_attributes(device))

        return devices

    def _populate(self):
        """Return the hosts and groups"""
        self.inventory.add_group("site")
        self.inventory.add_group("test")
        self.inventory.add_group("corp")
        self.inventory.add_group("ios")
        self.inventory.add_group("nxos")
        self.inventory.add_group("rkat1_datacenter")
        self.inventory.add_group("sast1_datacenter")
        self.inventory.add_group("asbc1_datacenter")

        corp_routing_devices = self._get_structured_inventory(
            "All_Cisco_Corp_Routing_Devices"
        )
        regexp = re.compile(r"\d{3}lb\d{2}")
        for device in corp_routing_devices:
            hostname = device["name"].lower()
            site = device["site"].split("\\")[-1].lower()

            group = site.replace("-", "_")
            self.inventory.add_group(group)

            if regexp.search(hostname):
                self.inventory.add_host(host=hostname, group="test")

            if "Nexus" in device["subTypeName"]:
                self.inventory.add_host(host=hostname, group="nxos")
                self.inventory.set_variable(hostname, "software", "NX-OS")
            else:
                self.inventory.add_host(host=hostname, group="ios")
                self.inventory.set_variable(hostname, "software", "IOS")

            if site.lower().startswith("rkat1"):
                self.inventory.add_host(host=hostname, group="rkat1_datacenter")
            elif site.lower().startswith("sast1"):
                self.inventory.add_host(host=hostname, group="sast1_datacenter")
            elif site.lower().startswith("asbc1") or site.lower().startswith("asgi1"):
                self.inventory.add_host(host=hostname, group="asbc1_datacenter")

            self.inventory.add_host(host=hostname, group=group)
            self.inventory.add_host(host=hostname, group="corp")

            self.inventory.set_variable(hostname, "subtype_name", device["subTypeName"])
            self.inventory.set_variable(hostname, "model_number", device["model"])
            self.inventory.set_variable(hostname, "ansible_host", device["mgmtIP"])
            self.inventory.set_variable(hostname, "serial_number", device["sn"])

    def parse(self, inventory, loader, path, cache):
        """Return dynamic inventory from source"""
        super(InventoryModule, self).parse(inventory, loader, path, cache)
        # Read the inventory YAML file
        self._read_config_data(path)
        try:
            # Store the options from the YAML file
            self.plugin = self.get_option("plugin")
            self.netbrain_url = os.environ["netbrain_url"]
            self.netbrain_username = os.environ["netbrain_username"]
            self.netbrain_password = os.environ["netbrain_password"]
            self.netbrain_tenant_name = os.environ["netbrain_tenant_name"]
            self.netbrain_domain_name = os.environ["netbrain_domain_name"]
            self.domain_name = os.environ["domain_name"]
        except Exception as e:
            raise AnsibleParserError(f"All correct options required: {e}")

        # Call our internal helper to populate the dynamic inventory
        self._populate()


class NetBrain:
    def __init__(self, url, username, password, verify=False):
        self.base_url = f"{url}/ServicesAPI/API/V1"
        self.verify = verify

        payload = {
            "username": username,
            "password": password,
        }

        response = requests.get(
            f"{self.base_url}/Session", json=payload, verify=self.verify
        )
        response.raise_for_status()

        # Capture the session token
        self.token = response.json()["token"]

        self.base_headers = {"Token": self.token}

    def get_tenants(self):
        response = requests.get(
            f"{self.base_url}/CMDB/Tenants",
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["tenants"]

    def get_domains(self, tenant_id):
        response = requests.get(
            f"{self.base_url}/CMDB/Domains",
            params={"tenantid": tenant_id},
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["domains"]

    def set_current_domain(self, tenant_id, domain_id):
        payload = {
            "tenantId": tenant_id,
            "domainId": domain_id,
        }
        response = requests.put(
            f"{self.base_url}/Session/CurrentDomain",
            json=payload,
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()

    def get_devices(self):
        response = requests.get(
            f"{self.base_url}/CMDB/Devices",
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["devices"]

    def get_device_groups(self):
        response = requests.get(
            f"{self.base_url}/CMDB/DeviceGroups",
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["deviceGroups"]

    def get_group_devices(self, group_name):
        url = f"{self.base_url}/CMDB/Devices/GroupDevices/{group_name}"
        response = requests.get(url, headers=self.base_headers, verify=self.verify)

        response.raise_for_status()
        return response.json()["devices"]

    def get_device_attributes(self, hostname):
        response = requests.get(
            f"{self.base_url}/CMDB/Devices/Attributes",
            params={"hostname": hostname},
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["attributes"]

    def get_device_config_file(self, hostname):
        params = {
            "hostname": hostname,
            "dataType": "ConfigurationFile",
        }

        response = requests.get(
            f"{self.base_url}/CMDB/DataEngine/DeviceData/Configuration",
            params=params,
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()

    def get_device_interfaces(self, hostname):
        response = requests.get(
            f"{self.base_url}/CMDB/Interfaces",
            params={"hostname": hostname},
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["interfaces"]

    def get_interface_attributes(self, hostname, interface_name):
        params = {
            "hostname": hostname,
            "interfaceName": interface_name,
        }

        response = requests.get(
            f"{self.base_url}/CMDB/Interfaces/Attributes",
            params=params,
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["attributes"]

    def get_interface_type_attributes(self, hostname, interface_type="ipIntfs"):
        params = {
            "hostname": hostname,
            "interfaceType": interface_type,
        }

        response = requests.get(
            f"{self.base_url}/CMDB/Interfaces/Attributes",
            params=params,
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["attributes"]

    def get_mac_addr_table(self, hostname):
        params = {"hostname": hostname, "dataType": 1, "tableName": "macTable"}

        response = requests.get(
            f"{self.base_url}/CMDB/Devices/DeviceRawData",
            params=params,
            headers=self.base_headers,
            verify=self.verify,
        )
        if response.status_code != 200:
            return None
        else:
            return response.json()["content"]

    def get_arp_cache_table(self, hostname):
        params = {"hostname": hostname, "dataType": 1, "tableName": "arpTable"}

        response = requests.get(
            f"{self.base_url}/CMDB/Devices/DeviceRawData",
            params=params,
            headers=self.base_headers,
            verify=self.verify,
        )
        if response.status_code != 200:
            return None
        else:
            return response.json()["content"]

    def get_interface_ipv4_addresses(self, hostname):
        ip_addrs = []
        for int in self.get_interface_type_attributes(hostname).keys():
            if not int.split()[1].endswith("/32") and not int.split()[1].startswith(
                "1."
            ):
                ip_addrs.append(int.split()[1])
        return ip_addrs

    def get_site_devices(self, site_path):
        params = {
            "sitePath": site_path,
        }
        response = requests.get(
            f"{self.base_url}/CMDB/Sites/Devices",
            params=params,
            headers=self.base_headers,
            verify=self.verify,
        )
        response.raise_for_status()
        return response.json()["devices"]
