#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58181);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/03/17 15:33:26 $");

  script_name(english:"Windows DNS Server Enumeration");
  script_summary(english:"Looks in the registry to see which DNS servers are in use");

  script_set_attribute(attribute:"synopsis", value:
"Nessus enumerated the DNS servers being used by the remote Windows
host.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the DNS servers configured on the remote
Windows host by looking in the registry.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");

get_kb_item_or_exit("SMB/registry_full_access");

login   = kb_smb_login();
pass    = kb_smb_password();
domain  = kb_smb_domain();
port    = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

r = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if ( r != 1 )
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}

key = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
dns_servers = make_array();
connections = make_array();

if (isnull(key_h))
{
  debug_print(strcat("Unable to open HKLM\" + key)); # don't exit since we might get useful info elsewhere
}
else
{
  # Check for the default nameserver values
  foreach name (make_list("DhcpNameServer", "NameServer"))
  {
    value = RegQueryValue(handle:key_h, item:name);
    if (!isnull(value) && value[1] =~ '^[0-9., ]+$')
      dns_servers['Default'][name] = value[1];
  }

  RegCloseKey(handle:key_h);
}

# Check nameservers configured for each interface
key = "SYSTEM\CurrentControlSet\Services\Tcpip\Parameters\Interfaces";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);

if (isnull(key_h))
  debug_print(strcat("Unable to open HKLM\" + key)); # don't exit since we might get useful info elsewhere
else
  info = RegQueryInfoKey(handle:key_h);

for (i=0; i < info[1]; ++i) # no need to do NULL checking on info since info[1] will evaluate to 0
{
  nameserver_found = FALSE;
  interface = RegEnumKey(handle:key_h, index:i);
  if (interface !~ '^{[0-9a-fA-F-]+}$') continue;

  key2 = key + "\" + interface;
  key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);

  if (isnull(key2_h))
  {
    debug_print(strcat("Unable to open HKLM\" + key2)); # don't exit since we might get useful info elsewhere
    continue;
  }

  foreach name (make_list("DhcpNameServer", "NameServer"))
  {
    value = RegQueryValue(handle:key2_h, item:name);
    if (!isnull(value) && value[1] =~ '^[0-9.,]+$')
    {
      nameserver_found = TRUE;
      dns_servers[interface][name] = value[1];
    }
  }

  RegCloseKey(handle:key2_h);

  # try to get the user friendly name of the connection this network adapter is related to
  if (nameserver_found)
  {
    key2 = "SYSTEM\CurrentControlSet\Control\Network\{4D36E972-E325-11CE-BFC1-08002BE10318}\" + interface + "\Connection";
    key2_h = RegOpenKey(handle:hklm, key:key2, mode:MAXIMUM_ALLOWED);

    if (!isnull(key2_h))
    {
      name = RegQueryValue(handle:key2_h, item:'Name');
      if (!isnull(name[1]))
        connections[interface] = name[1];

      RegCloseKey(handle:key2_h);
    }
  }
}

RegCloseKey(handle:key_h);
RegCloseKey(handle:hklm);
NetUseDel();

report = NULL;

foreach interface (keys(dns_servers))
{
  report += '\nInterface: ' + interface + '\n';

  name = connections[interface];
  if (!isnull(name))
    report += 'Network Connection : ' + name + '\n';

  foreach type (keys(dns_servers[interface]))
  {
    report += type + ': ' + dns_servers[interface][type] + '\n';

    if (' ' >< dns_servers[interface][type]) sep = ' ';
    else if (',' >< dns_servers[interface][type]) sep = ',';
    else sep = NULL;

    if (!isnull(sep))
    {
      servers = split(dns_servers[interface][type], sep:sep, keep:FALSE);

      foreach server (servers)
        set_kb_item(name:'SMB/nameserver/' + interface + '/' + type, value:server);
    }
    else set_kb_item(name:'SMB/nameserver/' + interface + '/' + type, value:dns_servers[interface][type]);
  }
}
if (isnull(report)) exit(0, 'The host does not appear to have any DNS servers configured.');

set_kb_item(name:'SMB/nameservers', value:TRUE);
if (report_verbosity > 0)
{
  report = '\nNessus enumerated DNS servers for the following interfaces :\n' + report;
  security_note(port:port, extra:report);
}
else security_note(port);
