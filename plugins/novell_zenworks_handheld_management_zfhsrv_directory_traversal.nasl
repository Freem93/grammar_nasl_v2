#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56668);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/11 13:40:20 $");

  script_cve_id("CVE-2011-4027");
  script_bugtraq_id(50369);
  script_osvdb_id(74197);

  script_name(english:"Novell ZENworks Handheld Management Common.dll messageID Request Field Parsing Traversal Arbitrary File Creation");
  script_summary(english:"Checks the file version of Common.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service affected by a directory traversal
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of the 'Common.dll' library included with the ZENworks
Handheld Management install on the remote Windows host is affected by
a directory traversal vulnerability because it fails to sanitize user
input to the 'messageID' field in requests of directory traversal
sequences.

An unauthenticated, remote attacker with knowledge of the name / ID of
the server can exploit this vulnerability to create arbitrary files on
the remote host within the context of the ZENworks Handheld Management
Server process.");
  script_set_attribute(attribute:"see_also", value:"http://aluigi.altervista.org/adv/zfhsrvr_1-adv.txt");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7009486");
  script_set_attribute(attribute:"solution", value:"Apply Novell hotfix TID 7009486.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/27");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_handheld_management");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("novell_zenworks_handheld_management_zfhipcnd_buffer_overflow.nasl", "smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/ZENworks/ZfHIPCND/Installed", "SMB/ZENworks/ZfHIPCND/Version");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("smb_func.inc");
include("misc_func.inc");

# exit if handheld management not installed at all
get_kb_item_or_exit("SMB/ZENworks/ZfHIPCND/Installed");

# Don't check if base version of ZENworks Handheld Manager > 7
version = get_kb_item("SMB/ZENworks/ZfHIPCND/Version");
if (!isnull(version))
{
  if (version !~ '^7\\.')
    exit(0, "The ZENworks Handheld Management Server "+version+" install on the host is not affected.");
}

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Connect to the appropriate share.
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

# Check whether it's installed.
path = NULL;

key = "SOFTWARE\Novell\ZENworks\Handheld Management\Server";
key_h = RegOpenKey(handle:hklm, key:key, mode:MAXIMUM_ALLOWED);
if (!isnull(key_h))
{
  value = RegQueryValue(handle:key_h, item:"InstallPath");
  if (!isnull(value))
  {
    path = value[1];
    path = ereg_replace(pattern:"^(.+)\\$", replace:"\1", string:path);
  }

  RegCloseKey(handle:key_h);
}

RegCloseKey(handle:hklm);
if (isnull(path))
{
  NetUseDel();
  exit(0, "Novell ZENworks Handheld Management Server is not installed.");
}


# Check the version of Common.dll (file that contains the vuln)
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\Common.dll", string:path);
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

if (isnull(fh))
{
  NetUseDel();
  exit(1, "Failed to open '"+path+"\Common.dll'.");
}

ver = GetFileVersion(handle:fh);
if (isnull(ver))
{
  CloseFile(handle:fh);
  NetUseDel();
  exit(1, "Could not get the version of '" + path + "\Common.dll'.");
}

installed_version = join(ver, sep:'.');
fixed_version = '7.1.4.10120';

CloseFile(handle:fh);
NetUseDel();

if (ver_compare(ver:installed_version, fix:fixed_version, strict:FALSE) == -1)
{
  if (report_paranoia < 2)
  {
      status = get_kb_item_or_exit("SMB/svc/ZENworks for Handhelds Server");
      if (status != SERVICE_ACTIVE)
        exit(0, "The host is not affected since the Handheld Management Server service is not active even though the version of Common.dll is "+installed_version+".");
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path + "\Common.dll" +
      '\n  Installed version : ' + installed_version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The ZENworks Handheld Management Server install on the host is not affected as the version of 'common.dll' is "+installed_version+".");
