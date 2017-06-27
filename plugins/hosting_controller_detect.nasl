#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19254);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:45 $");

  script_name(english:"Hosting Controller Software Detection");
  script_summary(english:"Detects Hosting Controller");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a web-hosting automation application
written in ASP or .NET.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Hosting Controller, a commercial
web-hosting automation suite for the Windows Server family platform.");
 script_set_attribute(attribute:"see_also", value:"http://hostingcontroller.com/");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"solution", value:"n/a");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("audit.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);


# Look in the registry for the version of Hosting Controller installed.
name = kb_smb_name();
port = kb_smb_transport();

login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();


# Connect to the remote registry.

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) exit(1);

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  exit(1);
}


# Determine the version / hotfix number of Hosting Controller.
ver = NULL;
hc_port = NULL;
hotfix = NULL;
# - version 7C.
key = "SOFTWARE\Advanced Communications\HostingController\General";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) ver = value[1];

  value = RegQueryValue(handle:key_h, item:"HCSitePort");
  if (!isnull(value)) hc_port = value[1];

  value = RegQueryValue(handle:key_h, item:"ServicePack");
  if (!isnull(value)) hotfix = value[1];

  RegCloseKey(handle:key_h);
}
# versions 6.x
if (isnull(ver) || isnull(hc_port))
{
  key = "SOFTWARE\Advanced Communications\Nt Web Hosting Controller\General";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h))
  {
    value = RegQueryValue(handle:key_h, item:"Version");
    if (!isnull(value)) ver = value[1];

    value = RegQueryValue(handle:key_h, item:"HCAdminSitePort");
    if (!isnull(value)) hc_port = value[1];

    value = RegQueryValue(handle:key_h, item:"LatestServicePack");
    if (!isnull(value)) hotfix = value[1];

    RegCloseKey(handle:key_h);
  }
}


# Clean up.
RegCloseKey(handle:hklm);
NetUseDel();


# Update the KB and report if it's installed.
if (!isnull(ver) && !isnull(hc_port))
{
  if (hotfix) ver = string(ver, " hotfix ", hotfix);

  set_kb_item(
    name:string("www/", hc_port, "/hosting_controller"),
    value:string(ver)
  );
  set_kb_item(name:"Services/hosting_controller", value:hc_port);

  report = string(
    "Hosting Controller ", ver, " was detected on the remote host with its\n",
    "administration interface running on this port."
  );
  security_note(port:hc_port, extra:report);
}
