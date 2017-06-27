#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(18559);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_name(english:"Rhapsody Detection");
  script_summary(english:"Detects Rhapsody");

 script_set_attribute(attribute:"synopsis", value:
"There is a music-playing application installed on the remote Windows
host.");
 script_set_attribute(attribute:"description", value:
"Rhapsody is installed on the remote Windows host. Rhapsody is a music
service and media player from RealNetworks.

Make sure the use of this program fits with your corporate security
policy.");
 script_set_attribute(attribute:"see_also", value:"http://www.rhapsody.com/");
 script_set_attribute(attribute:"solution", value:
"Remove this software if its use does not match your corporate security
policy.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2005/06/24");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


port = kb_smb_transport();
login = kb_smb_login();
pass = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm)) {
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Determine if it's installed.
key = "SOFTWARE\Wise Solutions\WiseUpdate\Apps\Rhapsody";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h)) {
  value = RegQueryValue(handle:key_h, item:"Version");
  if (!isnull(value)) ver = value[1];
  else ver = NULL;

  RegCloseKey(handle:key_h);
}
if (isnull(ver))
{
  key = "SOFTWARE\Wise Solutions\WiseUpdate\Apps\Listen Rhapsody";
  key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
  if (!isnull(key_h)) {
    value = RegQueryValue(handle:key_h, item:"Version");
    if (!isnull(value)) ver = value[1];
    else ver = NULL;

    RegCloseKey(handle:key_h);
  }
}
RegCloseKey(handle:hklm);
NetUseDel();


# Update KB and report findings.
if (!isnull(ver))
{
  set_kb_item(name:"SMB/Rhapsody/Version", value:ver);

  iver = split(ver, sep:'.', keep:FALSE);
  alt_ver = string(iver[0], " build ", iver[1], ".", iver[2], ".", iver[3]);
  report = string(
    "Version ", alt_ver, " of Rhapsody is installed.\n"
  );

  security_note(port:kb_smb_transport(), extra:report);
}
