#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(53536);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/11/18 19:03:16 $");

  script_cve_id("CVE-2011-0994");
  script_bugtraq_id(47144);
  script_osvdb_id(71980);

  script_name(english:"Novell File Reporter Agent XML Tag Handling Buffer Overflow");
  script_summary(english:"Checks NFR Agent version number");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a service that is vulnerable to a
remote buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The version of Novell File Reporter (NFR) Agent installed on the
remote Windows host is earlier than 1.0.4.2. Such versions reportedly
have a buffer overflow vulnerability because the service, which
listens by default on TCP port 3037, blindly copies user-supplied data
into a fixed-length buffer on the stack when handling the contents of
an XML tag.

An unauthenticated, remote attacker with access to the agent service
can leverage this issue to execute arbitrary code under the context of
the SYSTEM user.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-11-116/");
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/bugtraq/2011/Apr/30"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://download.novell.com/Download?buildid=rCAgCcbPH9s~"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Novell File Reporter 1.0.2, which includes NFR Agent
version 1.0.4.2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/22");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:file_reporter");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");


get_kb_item_or_exit("SMB/Registry/Enumerated");


# Unless we're paranoid, make sure the service is running.
if (report_paranoia < 2)
{
  status = get_kb_item_or_exit("SMB/svc/NFRAgentSvc");
  if (status != SERVICE_ACTIVE)
    exit(0, "The Novell File Reporter Agent service is installed but not active.");
}

# Connect to the appropriate share.
port    =  kb_smb_transport();
login   =  kb_smb_login();
pass    =  kb_smb_password();
domain  =  kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

# Connect to remote registry.
rc = NetUseAdd(login:login, password:pass, domain:domain, share:"IPC$");
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,"IPC$");
}

hklm = RegConnectRegistry(hkey:HKEY_LOCAL_MACHINE);
if (isnull(hklm))
{
  NetUseDel();
  audit(AUDIT_REG_FAIL);
}


# Find where it's installed.
path = NULL;

key = "SOFTWARE\Novell\File Reporter\Agent";
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
  exit(0, "Novell File Reporter Agent is not installed.");
}
NetUseDel(close:FALSE);


# Check the version of the main exe.
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);
exe =  ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1\NFRAgent.exe", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL,share);
}

fh = CreateFile(
  file               : exe,
  desired_access     : GENERIC_READ,
  file_attributes    : FILE_ATTRIBUTE_NORMAL,
  share_mode         : FILE_SHARE_READ,
  create_disposition : OPEN_EXISTING
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
  version = join(ver, sep:'.');
  fixed_version = '1.0.4.2';

  # nb: we're checking the file version so we don't have to worry about strict mode.
  if (ver_compare(ver:ver, fix:fixed_version) == -1)
  {
    if (report_verbosity > 0)
    {
      report =
        '\n  Path              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : ' + fixed_version + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
  exit(0, "Novell File Reporter Agent version "+version+" is installed and hence is not affected.");
}
else exit(1, "Couldn't get file version of '"+(share-'$')+":"+exe+"'.");
