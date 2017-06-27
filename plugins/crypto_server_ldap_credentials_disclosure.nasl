#
#  (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(23741);
  script_version("$Revision: 1.13 $");
 script_cvs_date("$Date: 2015/01/12 17:12:44 $");

  script_cve_id("CVE-2006-6145");
  script_bugtraq_id(21305);
  script_osvdb_id(30690);

  script_name(english:"CRYPTO-Server installvariables.properties LDAP Credential Local Disclosure");
  script_summary(english:"Checks for LDAP credentials left by InstallAnywhere");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
issue.");
 script_set_attribute(attribute:"description", value:
"A version of CRYPTOCard CRYPTO-Server, the server component of a
commercial two-factor authentication system, is installed on the
remote host.

When CRYPTO-Server was installed on the remote host, the installer
left credentials used to configure the application with Active
Directory in a log file, which by default is readable by anyone with
local access.");
 script_set_attribute(attribute:"solution", value:
"Change the credentials used by CRYPTO-Server for Active Directory and
JDBC.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/11/27");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/30");

script_set_attribute(attribute:"plugin_type", value:"local");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

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
key = "SOFTWARE\CRYPTOCard\Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallDir");
  if (!isnull(value)) path = value[1];

  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);
if (isnull(path)) {
  NetUseDel();
  exit(0);
}


# Look for credentials.
info = "";
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
log =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\UninstallerData\installvariables.properties", string:path);
NetUseDel(close:FALSE);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  exit(0);
}

fh = CreateFile(
  file:log,
  desired_access:GENERIC_READ,
  file_attributes:FILE_ATTRIBUTE_NORMAL,
  share_mode:FILE_SHARE_READ,
  create_disposition:OPEN_EXISTING
);
if (!isnull(fh))
{
  # Read up to 10K.
  chunk = 10240;
  size = GetFileSize(handle:fh);
  if (size > 0) {
    if (chunk > size) chunk = size;
    data = ReadFile(handle:fh, length:chunk, offset:0);

    if (data)
    {
      # Extract some interesting info for the report.
      matches = egrep(pattern:"^(LDAP|JDBC)_(USER|PASSWORD)=", string:data);
      if (matches)
      {
        foreach match (split(matches, keep:FALSE))
        {
          if (match !~ "=\*+$")
            info += "  " + match + '\n';
        }
      }
    }
  }
  CloseFile(handle:fh);
}


# Issue a report if any vulnerable files were found.
if (info)
{
    report = string(
    "The following credentials were left by the installer in the file\n",
    "'", path, "\\UninstallerData\\installvariables.properties' :\n",
    "\n",
    info
  );
  security_note(port:port, extra:report);
}

# Clean up.
NetUseDel();
