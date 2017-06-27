#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(25682);
  script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");

  script_cve_id("CVE-2007-3625");
  script_bugtraq_id(24790);
  script_osvdb_id(37839);

  script_name(english:"Citrix Presentation Server Clients Program Neighborhood Agent (PNAgent) Content Redirection Remote DoS");
  script_summary(english:"Checks version of PNAgent");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues.");
 script_set_attribute(attribute:"description", value:
"Citrix Presentation Server Client is installed on the remote host. It
is used to access published resources such as applications stored on
servers running Citrix Presentation Server.

The Program Neighborhood Agent component of the version of Citrix
Presentation Server Client on the remote host may allow for arbitrary
code execution if a user can be tricked into manually launching a
specially crafted file associated with the Program Neighborhood Agent.

It may also exit unexpectedly when attempting to access a file using
content redirection when its path exceeds 200 characters.");
 script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX113543");
 script_set_attribute(attribute:"see_also", value:"http://support.citrix.com/article/CTX113919" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Citrix Presentation Server Client for Windows version
10.100 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/06/26");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/06/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/10");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:citrix:metaframe_presentation_server");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("global_settings.inc");
include("smb_func.inc");
include("audit.inc");


# Connect to the appropriate share.
if (!get_kb_item("SMB/Registry/Enumerated")) exit(0);
name    =  kb_smb_name();
port    =  kb_smb_transport();

login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();



if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
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


# Check whether it's installed.
path = NULL;
key = "SOFTWARE\Citrix\Install\PNAgent";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallFolder");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }
  RegCloseKey (handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0);
}


# Determine the version from PNAgent itself.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\pnagent.exe", string:path);
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
if (!isnull(fh))
{
  ver = GetFileVersion(handle:fh);
  CloseFile(handle:fh);

  # There's a problem if the version of PNAgent is < 10.100
  if (
    !isnull(ver) &&
    (
      ver[0] < 10 ||
      (ver[0] == 10 && ver[1] < 100)
    )
  )
  {
    version = string(ver[0], ".", ver[1], ".", ver[2]);
    report = string(
      "Version ", version, " of the Program Neighborhood Agent is installed\n",
      "under :\n",
      "\n",
      "  ", path, "\n"
    );
    security_warning(port:port, extra:report);
  }
}


# Clean up.
NetUseDel();
