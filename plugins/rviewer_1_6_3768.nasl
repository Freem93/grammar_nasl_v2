#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(26062);
  script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2015/01/12 17:12:47 $");

  script_cve_id("CVE-2007-4750", "CVE-2007-4751");
  script_bugtraq_id(25591);
  script_osvdb_id(40544, 40545);

  script_name(english:"R-Viewer < 1.6.3768 Multiple Vulnerabilities");
  script_summary(english:"Checks version of rview.exe");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by multiple
issues.");
 script_set_attribute(attribute:"description", value:
"R-Viewer, a secure document viewer from remotedocs.com, is installed
on the remote host.

According to the registry, the installation of R-Viewer on the remote
Windows host allows arbitrary code to be executed without a user's
knowledge and stores unencrypted copies of previously-opened documents
in temporary directories. If an attacker can trick a user into opening
a specially crafted RDZ file, he can leverage these issues to view
files or execute code on the affected system subject to the user's
privileges.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96b96330");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/479718" );
 script_set_attribute(attribute:"solution", value:"Upgrade to R-Viewer version 1.6.3768 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(310);

 script_set_attribute(attribute:"plugin_publication_date", value:"2007/09/18");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("smb_func.inc");


# Connect to the appropriate share.

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "KB 'SMB/Registry/Enumerated' not set to TRUE.");

port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
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


# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Classes\RemoteDocs.PackageFile\Shell\Open\Command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:'^"([^"]+)".*', replace:"\1", string:path);
    if (ereg(pattern:"rview\.exe ?", string:path, icase:TRUE))
      path = ereg_replace(pattern:"^(.+)\\\[^\]+\.exe( .+)?$", replace:"\1", string:path);
    else path = NULL;
  }

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\rview.exe", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
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
  # nb: the fileversion for rview.exe from 1.6.3768 is 1.6.0.3763.
  fix = split("1.6.0.3763", sep:'.', keep:FALSE);
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
