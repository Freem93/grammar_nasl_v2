#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34243);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2017/05/16 19:43:12 $");

  script_cve_id("CVE-2008-2468");
  script_bugtraq_id(31193);
  script_osvdb_id(48123);
  script_xref(name:"Secunia", value:"31888");

  script_name(english:"LANDesk Multiple Products QIP Server Service (qipsrvr.exe) Heal Request Packet Handling Overflow");
  script_summary(english:"Checks version of qipsrvr.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a
remote buffer overflow vulnerability.");
 script_set_attribute(attribute:"description", value:
"LANDesk Management Suite, used to automate system and security
management tasks, is installed on the remote host.

The version of LANDesk Management Suite includes an instance of the
Intel QIP Server Service that makes a call to 'MultiByteToWideChar()'
using values from packet data. Using a specially crafted 'heal'
request, a remote attacker can leverage this issue to control both the
pointer to the function's 'StringToMap' and 'StringSize' arguments,
overflow a stack or heap buffer depending on the specified sizes, and
execute arbitrary code with SYSTEM privileges.");
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-08-06");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2008/Sep/300" );
 script_set_attribute(attribute:"see_also", value:"https://community.landesk.com/docs/DOC-3276" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to LANDesk 8.7 / 8.8 if necessary and apply the appropriate
fix referenced in the vendor advisory.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(119);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/19");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_enum_services.nasl", "smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Make sure the affected service is running, unless we're being paranoid.
if (report_paranoia < 2)
{
  services = get_kb_item("SMB/svcs");
  if (services && "Intel QIP Server" >!< services) exit(0);
}


# Connect to the appropriate share.
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  exit(0);
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(0);
}


# Make sure it's installed.
path = NULL;

key = "SOFTWARE\LANDesk\ManagementSuite\Setup";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  # If LANDesk is installed...
  item = RegQueryValue(handle:key_h, item:"LdmainPath");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey(handle:key_h);
}
if (isnull(path))
{
  key = "SYSTEM\CurrentControlSet\Services\Intel QIP Server Service";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    item = RegQueryValue(handle:key_h, item:"ImagePath");
    if (!isnull(item))
    {
      path = item[1];
      path = ereg_replace(pattern:'^"?(.+)\\\\qipsrvr\\.exe"?.*', replace:"\1", string:path);
    }

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  NetUseDel();
  exit(0);
}


# Grab the version from the executable.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\qipsrvr.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:exe,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
ver = NULL;
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);
}
NetUseDel();


# Check the version number.
if (!isnull(ver))
{
  if (ver[0] == 8 && ver[1] == 80) fix_version = "8.80.2.4";
  else if (
    ver[0] < 8 ||
    (ver[0] == 8 && ver[1] <= 70)
  ) fix_version = "8.70.7.2";
  else exit(0);

  fix = split(fix_version, sep:'.', keep:FALSE);
  for (i=0; i<max_index(fix); i++)
    fix[i] = int(fix[i]);

  for (i=0; i<max_index(ver); i++)
    if ((ver[i] < fix[i]))
    {
      security_hole(port);
      break;
    }
    else if (ver[i] > fix[i])
      break;
}

