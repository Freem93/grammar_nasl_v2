#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25125);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2007-2475", "CVE-2007-2476");
  script_bugtraq_id(23547);
  script_osvdb_id(35774, 35775);

  script_name(english:"Novell SecureLogin < 6.0.106 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Novell SecureLogin");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an application that is affected by
multiple issues.");
  script_set_attribute(attribute:"description", value:
"The version of Novell SecureLogin installed on the remote host is
earlier than 6.0.106. Such versions reportedly grant a user excessive
permissions to their own attributes in an Active Directory (AD)
environment.

There is also a security issue with AD password change.

Note that Novell strongly recommends the patch be applied if operating
in an Active Directory environment regardless of whether SecureLogin
is deployed in eDirectory or AD mode.");
  # http://support.novell.com/docs/Readmes/InfoDocument/patchbuilder/readme_5003822.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b56c5a09");
  script_set_attribute(attribute:"solution", value:"Apply Novell SecureLogin 6.0.106 patch or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/02");

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

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

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


# Get some info about the install.
path = NULL;

key = "SOFTWARE\Novell\SecureLogin";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  item = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(item))
  {
    path = item[1];
    if ("\SecretStore" >< path) path = path - "\SecretStore";
  }
  RegCloseKey(handle:key_h);
}
RegCloseKey(handle:hklm);


# If it is...
if (path)
{
  NetUseDel(close:FALSE);

  # Make sure the executable exists.
  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
  exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\slbroker.exe", string:path);
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
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    CloseFile(handle:fh);
  }

  # There's a problem if the version is < 6.0.106.0.
  if (!isnull(ver))
  {
    fix = split("6.0.106.0", sep:'.', keep:FALSE);
    for (i=0; i<4; i++)
      fix[i] = int(fix[i]);

    for (i=0; i<max_index(ver); i++)
      if ((ver[i] < fix[i]))
      {
        version = string(ver[0], ".", ver[1], ".", ver[2]);

        report = string(
          "Novell SecureLogin version ", version, " is installed under :\n",
          "\n",
          "  ", path, "\n"
        );
        security_hole(port:port, extra:report);

        break;
      }
      else if (ver[i] > fix[i])
        break;
  }
}
NetUseDel();
