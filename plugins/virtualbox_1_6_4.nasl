#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33819);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2015/01/12 17:12:50 $");

  script_cve_id("CVE-2008-3431");
  script_bugtraq_id(30481);
  script_osvdb_id(47424);
  script_xref(name:"Secunia", value:"31361");

  script_name(english:"Sun xVM VirtualBox < 1.6.4 Local Privilege Escalation");
  script_summary(english:"Checks VirtualBox version");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by a local
privilege escalation vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Sun xVM VirtualBox, an open
source virtualization platform, before 1.6.4. Such versions reportedly
include a kernel driver, 'VBoxDrv.sys', that allows a local user to
open the device '\\.\VBoxDrv' and issue IOCTLs with a buffering method
of 'METHOD_NEITHER' without any validation. Using specially crafted
input, an unprivileged user can leverage this issue to execute
arbitrary code in kernel mode.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ec7bf70b");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/495095/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://virtualbox.org/wiki/Changelog" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Sun xVM VirtualBox 1.6.4 or later.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/05");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:sun:xvm_virtualbox");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("audit.inc");
include("smb_hotfixes.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


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
version = NULL;

key = "SOFTWARE\Sun\xVM VirtualBox";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  item = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(item)) version = item[1];

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path) || isnull(version))
{
  NetUseDel();
  exit(0);
}


# Make sure the driver is actually installed.
winroot = hotfix_get_systemroot();
if (!winroot) exit(1);

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:winroot);
sys =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\System32\drivers\VBoxDrv.sys", string:winroot);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:sys,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  CloseFile(handle:fh);
}
else
{
  path = NULL;
  version = NULL;
}
NetUseDel();


# Issue a report if it's an affected version.
if (!isnull(version) && version =~ "^1\.6\.[0-3]($|[^0-9])")
{
  if (report_verbosity)
  {
    report = string(
      "\n",
      "The kernel driver from version ", version, " is installed as :\n",
      "\n",
      "  ", winroot, "\\System32\\drivers\\VBoxDrv.sys"
    );
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
}
