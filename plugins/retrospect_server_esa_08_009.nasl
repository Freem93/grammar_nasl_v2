#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(33562);
  script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2016/05/16 14:22:07 $");

  script_cve_id("CVE-2008-3288");
  script_bugtraq_id(30319);
  script_osvdb_id(47505);
  script_xref(name:"Secunia", value:"31186");

  script_name(english:"Retrospect Backup Server Authentication Module Password Hash Weakness (ESA-08-009)");
  script_summary(english:"Checks version of Retrospect server");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by an
information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"According to its version number, the Authentication Module in the
Retrospect Backup Server installed on the remote host uses a weak hash
algorithm to hash a user's password, which could allow a remote
attacker to gain control of a client's machine.");
 script_set_attribute(attribute:"see_also", value:"http://www.fortiguardcenter.com/advisory/FGA-2008-16.html");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/494560/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://kb.dantz.com/article.asp?article=9692&p=2" );
 script_set_attribute(attribute:"solution", value:"Upgrade to Retrospect Backup Server version 7.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(310);

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/23");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");


# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1) {
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}


# Connect to remote registry.
hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Make sure it's installed.
exe = NULL;
path = NULL;

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\Retrospect.exe";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) exe = item[1];

  item = RegQueryValue(handle:key_h, item:"Path");
  if (!isnull(item))
  {
    path = item[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(exe) || isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the file version.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
exe2 = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file:exe2,
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


# If it's an affected version...
if (
  !isnull(ver) &&
  (
    ver[0] < 7 ||
    (ver[0] == 7 && ver[1] < 6)
  )
)
{
  if (report_verbosity)
  {
    version = string(ver[0], ".", ver[1], ".", ver[2]);
    report = string(
      "\n",
      "Retrospect Backup Server version ", version, " is installed on\n",
      "the remote host under :\n",
      "\n",
      "  ", path, "\n"
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
