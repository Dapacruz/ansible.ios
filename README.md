# ansible.ios

Ansible playbooks for managing Cisco IOS and NX-OS network devices. This project is designed primarily for use with **Ansible Automation Platform (AAP)**, where playbooks are launched as job templates with survey variables. It includes a custom dynamic inventory plugin backed by NetBrain and integrates with ServiceNow for incident-driven automation.

---

## Table of Contents

- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
  - [Environment Variables](#environment-variables)
- [Dynamic Inventory](#dynamic-inventory)
- [Playbooks](#playbooks)
  - [backup\_configuration](#backup_configuration)
  - [backup\_configuration\_routers](#backup_configuration_routers)
  - [execute\_op\_command](#execute_op_command)
  - [shutdown\_interface](#shutdown_interface)
  - [no\_shutdown\_interface](#no_shutdown_interface)
  - [default\_interface](#default_interface)
  - [get\_device\_state\_snapshot](#get_device_state_snapshot)
  - [snow\_attach\_device\_state\_snapshot](#snow_attach_device_state_snapshot)
  - [snow\_attach\_store\_diagnostic\_report](#snow_attach_store_diagnostic_report)
- [Ansible Automation Platform Usage](#ansible-automation-platform-usage)
- [Ansible CLI Usage](#ansible-cli-usage)
- [Troubleshooting](#troubleshooting)
- [License](#license)

---

## Requirements

### Ansible Collections

Install the required Ansible collections:

```bash
ansible-galaxy collection install cisco.ios
ansible-galaxy collection install servicenow.itsm
ansible-galaxy collection install community.general
```

Or use a `requirements.yml` and install all at once:

```yaml
# requirements.yml
collections:
  - name: cisco.ios
  - name: servicenow.itsm
  - name: community.general
```

```bash
ansible-galaxy collection install -r requirements.yml -p collections/
```

### Python Dependencies

The device state snapshot playbooks require the following Python packages on the Ansible execution environment (or control node):

```bash
pip install pandas xlsxwriter requests
```

### External Services

| Service | Purpose |
|---|---|
| [NetBrain](https://www.netbraintech.com/) | Dynamic inventory source — provides device hostname, management IP, site, model, and serial number |
| [ServiceNow](https://www.servicenow.com/) | Incident management — playbooks can update work notes and attach diagnostic reports |
| Cisco vManage | SD-WAN status data for store diagnostic reports |
| Juniper Mist | Wireless AP data for store diagnostic reports |

---

## Installation

1. Clone this repository:

   ```bash
   git clone <repository-url>
   cd ansible.ios
   ```

2. Install Ansible collections:

   ```bash
   ansible-galaxy collection install -r requirements.yml -p collections/
   ```

3. Set the required environment variables (see [Configuration](#configuration)).

4. Verify the inventory plugin can reach NetBrain:

   ```bash
   ansible-inventory -i cisco_inventory.yml --list
   ```

---

## Configuration

### Environment Variables

The following environment variables must be set before running playbooks. In AAP, these are configured as credentials or environment variables on the job template.

#### NetBrain Inventory Plugin

| Variable | Description |
|---|---|
| `netbrain_url` | Base URL for the NetBrain API (e.g., `https://netbrain.example.com`) |
| `netbrain_username` | NetBrain service account username |
| `netbrain_password` | NetBrain service account password |
| `netbrain_tenant_name` | NetBrain tenant name |
| `netbrain_domain_name` | NetBrain domain name |
| `domain_name` | Network domain name used for device resolution |

#### ServiceNow

| Variable | Description |
|---|---|
| `snow_instance` | ServiceNow instance URL (e.g., `https://example.service-now.com`) |
| `snow_username` | ServiceNow service account username |
| `snow_password` | ServiceNow service account password |

#### Email (Device State Snapshot)

| Variable | Description |
|---|---|
| `smtp_server` | SMTP relay hostname |
| `smtp_port` | SMTP relay port |
| `smtp_from` | Sender email address |
| `smtp_to` | Recipient email address |

---

## Dynamic Inventory

The custom inventory plugin (`inventory_plugins/cisco_plugin.py`) queries NetBrain to build a dynamic inventory of Cisco devices. It organizes hosts into the following groups:

| Group | Contents |
|---|---|
| `corp` | All corporate network devices |
| `ios` | Devices running Cisco IOS |
| `nxos` | Devices running Cisco NX-OS |
| `edge` | Corporate edge routers |
| `wan` | Corporate WAN routers |
| `test` | Lab/test devices (matched by hostname pattern) |
| `rkat1_datacenter` | Devices in the RKAT1 datacenter |
| `sast1_datacenter` | Devices in the SAST1 datacenter |
| `asbc1_datacenter` | Devices in the ASBC1/ASGI1 datacenter |
| `<site_name>` | Dynamic per-site groups derived from NetBrain site paths |

Each host is populated with the following variables:

| Variable | Source |
|---|---|
| `ansible_host` | Management IP from NetBrain |
| `ansible_network_os` | `ios` or `nxos` based on device group |
| `software` | `IOS` or `NX-OS` |
| `subtype_name` | Device sub-type from NetBrain |
| `model_number` | Device model from NetBrain |
| `serial_number` | Device serial number from NetBrain |

The inventory source file is `cisco_inventory.yml`:

```yaml
---
plugin: cisco_plugin
```

---

## Playbooks

All playbooks are located in the `playbooks/` directory. Most playbooks use `hosts_limit` as an extra variable to target specific hosts or groups — this maps to the AAP job template **Limit** field or can be passed via `--limit` on the CLI.

### backup_configuration

**File:** `playbooks/backup_configuration.yml`

Backs up the running configuration of IOS devices to a date-stamped directory.

**Output:** `/configurations/ios/configuration_backups/<YYYY-MM-DD>/<hostname>.config`

| Extra Variable | Type | Description |
|---|---|---|
| `hosts_limit` | string | Target host(s) or group |

---

### backup_configuration_routers

**File:** `playbooks/backup_configuration_routers.yml`

Backs up the running configuration of IOS routers to a static directory (no date stamp).

**Output:** `/configurations/ios/configuration_backups/routers/<hostname>.config`

| Extra Variable | Type | Description |
|---|---|---|
| `hosts_limit` | string | Target host(s) or group |

---

### execute_op_command

**File:** `playbooks/execute_op_command.yml`

Executes a single operational (show) command on one or more IOS devices and prints the output.

| Extra Variable | Type | Description |
|---|---|---|
| `hosts_limit` | string | Target host(s) or group |
| `command` | string | IOS show command to execute (e.g., `show ip interface brief`) |

---

### shutdown_interface

**File:** `playbooks/shutdown_interface.yml`

Shuts down one or more interfaces on IOS devices and saves the running configuration if modified.

| Extra Variable | Type | Description |
|---|---|---|
| `hosts_limit` | string | Target host(s) or group |
| `interfaces` | list | List of interface names to shut down (e.g., `["GigabitEthernet0/1"]`) |

---

### no_shutdown_interface

**File:** `playbooks/no_shutdown_interface.yml`

Brings up one or more interfaces on IOS devices and saves the running configuration if modified.

| Extra Variable | Type | Description |
|---|---|---|
| `hosts_limit` | string | Target host(s) or group |
| `interfaces` | list | List of interface names to enable (e.g., `["GigabitEthernet0/1"]`) |

---

### default_interface

**File:** `playbooks/default_interface.yml`

Resets one or more interfaces to default configuration, sets a description, and shuts them down. Saves the running configuration if modified.

| Extra Variable | Type | Description |
|---|---|---|
| `hosts_limit` | string | Target host(s) or group |
| `interfaces` | list | List of objects with `name` and `description` keys |

Example `interfaces` value:
```json
[{"name": "GigabitEthernet0/1", "description": "UNUSED"}]
```

---

### get_device_state_snapshot

**File:** `playbooks/get_device_state_snapshot.yml`

Gathers a comprehensive state snapshot from an IOS or NX-OS device. Data is collected, rendered into CSV files, merged into a formatted Excel workbook, and emailed to the configured recipient.

**Collected data includes:**
- Running configuration (optional)
- Software version
- IP interfaces
- ARP cache
- Routing table
- OSPF neighbors
- BGP neighbors

**Output:** `playbooks/output/<hostname>/`
- `<hostname>_device_state_snapshot_<timestamp>.xlsx` — Excel workbook with all data as formatted tables
- `<hostname>_device_state_snapshot_<timestamp>.txt` — Plain-text summary

| Extra Variable | Type | Default | Description |
|---|---|---|---|
| `hosts_limit` | string | — | Target host(s) or group |
| `save_config` | boolean | — | Set to `true` to include running config in output |

Requires SMTP environment variables to be set for the email task.

---

### snow_attach_device_state_snapshot

**File:** `playbooks/snow_attach_device_state_snapshot.yml`

Gathers the same device state snapshot as `get_device_state_snapshot` and attaches the resulting Excel workbook to a ServiceNow incident as an attachment.

| Extra Variable | Type | Description |
|---|---|---|
| `configuration_item` | string | Device hostname (must match inventory) |
| `snow_incident` | string | ServiceNow incident number (e.g., `INC0012345`) |
| `save_config` | boolean | Set to `true` to include running config in output |

Requires ServiceNow environment variables.

---

### snow_attach_store_diagnostic_report

**File:** `playbooks/snow_attach_store_diagnostic_report.yml`

Generates a comprehensive store network diagnostic report and attaches it to a ServiceNow incident. This playbook gathers data from multiple sources in parallel, renders a diagnostic report, and updates the incident's work notes.

**Data sources:**

| Source | Data Collected |
|---|---|
| ServiceNow | Store details, network info, WAN circuits, recent incidents |
| Store Switch | Interface status, MAC address table, ARP cache |
| MPLS Router | Interface status, routing table, OSPF/BGP neighbors |
| Firewall (Palo Alto) | Interface and security state |
| Cisco vManage | SD-WAN tunnel and transport status |
| Juniper Mist | Wireless AP status |

**Tags:**
- `diagnostic_report` — Renders and attaches the full diagnostic report
- `work_notes` — Renders and publishes work notes to the incident

| Extra Variable | Type | Description |
|---|---|---|
| `snow_incident` | string | ServiceNow incident number (e.g., `INC0012345`) |
| `recent_incidents` | string (JSON) | Optional JSON array of recent related incidents |

Requires ServiceNow environment variables.

---

## Ansible Automation Platform Usage

This project is designed to be used with **Ansible Automation Platform (AAP)**. The recommended setup is:

1. **Project** — Sync this repository as an AAP project (SCM type: Git).

2. **Credentials** — Create credential objects for:
   - Network device SSH access (`Machine` credential type)
   - NetBrain API access (custom credential type with the env vars listed above)
   - ServiceNow access (custom credential type with `snow_*` env vars)

3. **Inventory** — Create an inventory using the `cisco_inventory.yml` source file and the `cisco_plugin` inventory plugin. The plugin will dynamically populate hosts from NetBrain on each sync.

4. **Job Templates** — Create a job template per playbook. Use **Surveys** to collect required extra variables (e.g., `hosts_limit`, `snow_incident`, `interfaces`) from the operator at launch time.

5. **Execution Environment** — Use or build an execution environment that includes the required collections and Python packages (`pandas`, `xlsxwriter`, `requests`).

---

## Ansible CLI Usage

While AAP is the primary target, all playbooks can be run directly from the command line.

### Prerequisites

Export the required environment variables:

```bash
export netbrain_url="https://netbrain.example.com"
export netbrain_username="svc-ansible"
export netbrain_password="<password>"
export netbrain_tenant_name="MyTenant"
export netbrain_domain_name="MyDomain"
export domain_name="example.com"
```

### Run a playbook

```bash
# Execute a show command on a single device
ansible-playbook playbooks/execute_op_command.yml \
  -i cisco_inventory.yml \
  -e "hosts_limit=router01" \
  -e "command='show ip interface brief'"

# Back up configurations for all IOS devices
ansible-playbook playbooks/backup_configuration.yml \
  -i cisco_inventory.yml \
  -e "hosts_limit=ios"

# Shut down interfaces on a device
ansible-playbook playbooks/shutdown_interface.yml \
  -i cisco_inventory.yml \
  -e "hosts_limit=switch01" \
  -e '{"interfaces": ["GigabitEthernet0/1", "GigabitEthernet0/2"]}'

# Get a device state snapshot
ansible-playbook playbooks/get_device_state_snapshot.yml \
  -i cisco_inventory.yml \
  -e "hosts_limit=router01" \
  -e "save_config=true"

# Attach a device state snapshot to a ServiceNow incident
ansible-playbook playbooks/snow_attach_device_state_snapshot.yml \
  -i cisco_inventory.yml \
  -e "configuration_item=router01" \
  -e "snow_incident=INC0012345" \
  -e "save_config=false"
```

---

## Troubleshooting

**Inventory plugin returns no hosts**
- Verify all `netbrain_*` environment variables are exported and correct.
- Confirm the NetBrain tenant and domain names match exactly (case-sensitive).
- Test connectivity to the NetBrain API: `curl -k <netbrain_url>/ServicesAPI/API/V1/Session`

**Playbook fails with `ansible_network_os` undefined**
- This variable is set by the inventory plugin. Ensure you are using `cisco_inventory.yml` as the inventory source, not a static inventory file.

**Excel workbook task fails**
- Ensure `pandas` and `xlsxwriter` are installed in the Python environment used by the Ansible controller or execution environment:
  ```bash
  pip install pandas xlsxwriter
  ```

**ServiceNow tasks fail with 401 Unauthorized**
- Verify the `snow_instance`, `snow_username`, and `snow_password` environment variables are set and that the service account has sufficient permissions in ServiceNow.

**`get_device_state_snapshot` email task is silently skipped**
- The mail task uses `ignore_errors: true`. Check that `smtp_server`, `smtp_port`, `smtp_from`, and `smtp_to` are all set.

---

## License

MIT License — Copyright (c) 2019 David Cruz. See [LICENSE](LICENSE) for full text.
