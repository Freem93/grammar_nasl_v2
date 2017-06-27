#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(21782);
  script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/08/03 13:57:40 $");

  script_cve_id("CVE-2006-1467");
  script_bugtraq_id(18730);
  script_osvdb_id(26909);

  script_name(english:"Apple iTunes AAC File Parsing Integer Overflow (credentialed check)");
  script_summary(english:"Check the version of iTunes");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains an application that is affected by a
remote code execution flaw.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Apple iTunes, a popular media player.

The remote version of iTunes is vulnerable to an integer overflow when
it parses a specially crafted AAC file. By tricking a user into
opening such a file, a remote attacker may be able to leverage this
issue to execute arbitrary code on the affected host, subject to the
privileges of the user running the application.");
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/advisories/10781");
 script_set_attribute(attribute:"see_also", value:"http://lists.apple.com/archives/security-announce/2006/Jun/msg00001.html");
 script_set_attribute(attribute:"solution", value:"Upgrade to Apple iTunes 6.0.5 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/06/29");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/30");

script_set_attribute(attribute:"plugin_type", value:"local");
script_set_attribute(attribute:"cpe", value:"cpe:/a:apple:itunes");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


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


# Get some info about the install.
exe = NULL;
key = "SOFTWARE\Classes\Applications\iTunes.exe\shell\open\command";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:NULL);
  if (!isnull(item)) exe = item[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (exe)
{
  # Determine its version from the executable itself.
  exe = ereg_replace(pattern:'^"([^"]+)".*$', replace:"\1", string:exe);

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:exe);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:exe);
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
  }

  # There's a problem if the version is before 6.0.5.
  if (!isnull(ver))
  {
    if (
      ver[0] < 6 ||
      (ver[0] == 6 && ver[1] == 0 && ver[2] < 5)
    ) security_warning(kb_smb_transport());
  }
}


# Clean up.
NetUseDel();
