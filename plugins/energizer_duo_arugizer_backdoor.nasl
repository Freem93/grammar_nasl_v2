#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45006);
  script_version("$Revision: 1.9 $");
 script_cvs_date("$Date: 2015/05/01 13:43:00 $");

  script_cve_id("CVE-2010-0103");
  script_bugtraq_id(38571);
  script_osvdb_id(62782);
  script_xref(name:"CERT", value:"154421");

  script_name(english:"Energizer DUO USB Battery Charger Software Backdoor (credentialed check)");
  script_summary(english:"Looks for Arucer.dll in conjunction with UsbCharger software");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host has a backdoor.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host includes an install of the Energizer DUO
software, likely included with a Energizer DUO USB battery charger to
allow a user to view the battery charging status.

The installed version of this software includes the Arugizer backdoor
(Arucer.dll), which is reported to have been distributed with the
Energizer DUO software.

An unauthenticated, remote attacker who connects to this port can use
the backdoor to list directories, send and receive files, and execute
programs.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?fba833e0");
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b341c9b0"
  );
  script_set_attribute(attribute:"solution", value:
"Verify whether the remote host has been compromised and reinstall the
operating system if necessary.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Energizer DUO USB Battery Charger Arucer.dll Trojan Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Backdoors");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();
#if (!get_port_state(port)) exit(0, "Port "+port+" is not open.");
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

#soc = open_sock_tcp(port);
#if (!soc) exit(1, "Failed to open a socket on port "+port+".");

#session_init(socket:soc, hostname:name);
if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Unless we're paranoid, make sure UsbCharger software is (or was) installed.
if (report_paranoia < 2)
{
  installed = FALSE;

  rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
  if (rc != 1)
  {
    NetUseDel();
    exit(1, "Can't connect to IPC$ share.");
  }

  # Scan through the Installer's list of software.
  list = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (!isnull(list))
  {
    foreach name (keys(list))
    {
      prod = list[name];
      if (prod && prod =~ "Energizer UsbCharger")
      {
        installed = TRUE;
        break;
      }
    }
  }

  if (!installed)
  {
    # Connect to remote registry.
    hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
    if (isnull(hklm))
    {
      NetUseDel();
      exit(1, "Can't connect to remote registry.");
    }

    key = "SOFTWARE\UsbCharger";
    key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
    if (!isnull(key_h))
    {
      installed = TRUE;
      RegCloseKey(handle:key_h);
    }

    RegCloseKey(handle:hklm);
  }
  if (!installed)
  {
    NetUseDel();
    exit(0, "No trace of the Energizer DUO software was found.");
  }
  NetUseDel(close:FALSE);
}


# Check for the backdoor itself.
path = hotfix_get_systemroot();
if (!path) exit(1, "Can't get system root.");
report = "";

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
dll =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\system32\Arucer.dll", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(1, "Can't connect to "+share+" share.");
}

fh = CreateFile(
  file:dll,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  report = '\n' +
    'Nessus found the backdoor installed as :\n' +
    '\n' +
    '  ' + path + '\\system32\\Arucer.dll';

  CloseFile(handle:fh);
}
NetUseDel();


# Issue a report if necessary.
if (report)
{
  if (report_verbosity > 0) security_hole(port:port, extra:report);
  else security_hole(port);

  exit(0);
}
else exit(0, "The backdoor was not found.");
