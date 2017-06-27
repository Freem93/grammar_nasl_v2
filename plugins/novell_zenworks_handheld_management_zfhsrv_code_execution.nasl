#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56684);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/01/12 17:12:46 $");

  script_cve_id("CVE-2011-2655", "CVE-2011-2656");
  script_bugtraq_id(50303);
  script_osvdb_id(76820, 76821);

  script_name(english:"Novell ZENworks Handheld Management ZfHSrvr.exe Multiple Remote Code Execution Vulnerabilities");
  script_summary(english:"Checks the version of ZfHSrvr.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a service affected by multiple remote code
execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The ZENworks Handheld Management Server process (ZfHSrvr.exe) contains
multiple unspecified remote code execution vulnerabilities that allow
an attacker to run arbitrary code on a victim within the context of
the 'ZENworks Handheld Management Server' process.");
  # http://www.novell.com/support/search.do?cmd=displayKC&docType=kc&externalId=7009489
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dd2aa583");
  script_set_attribute(attribute:"solution", value:"Apply Novell hotfix TID 7009489.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:zenworks_handheld_management:7");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

# don't check if base version of zendworks handheld manager > 7
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


# Check the version of ZfHSrvr.exe
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\ZfHSrvr.exe", string:path);
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

if (isnull(ver))
{
  CloseFile(handle:fh);
  NetUseDel();
  exit(1, "Could not get the version of '" + path + "\ZfhSrvr.exe'.");
}

ver = GetFileVersion(handle:fh);
if (isnull(ver)) exit(1, "Could not get version on file 'ZfHSrvr.exe'.");

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
        exit(0, "The host is not affected since the Handheld Management Server service is not active even though the version of ZfHSrvr.exe is "+installed_version+".");
  }

  if (report_verbosity > 0)
  {
    report =
      '\n  File              : ' + path + "\ZfHSrvr.exe" +
      '\n  Installed version : ' + installed_version +
      '\n  Fixed version     : ' + fixed_version + '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0);
}
else exit(0, "The ZENworks Handheld Management Server install on the host is not affected as the version of 'ZfHSrvr.exe' is "+installed_version+".");
