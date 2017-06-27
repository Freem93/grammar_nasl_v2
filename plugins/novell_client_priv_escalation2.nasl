#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69557);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/11/23 20:31:34 $");

  script_cve_id("CVE-2013-3956", "CVE-2013-3697");
  script_bugtraq_id(60202, 60203);
  script_osvdb_id(93718, 93723);
  script_xref(name:"EDB-ID", value:"26452");
  script_xref(name:"EDB-ID", value:"27191");

  script_name(english:"Novell Client / Client 2 Multiple Vulnerabilities");
  script_summary(english:"Checks version of acu.exe or nicm.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a client application installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Novell Client or Novell Client 2 installed on the remote
Windows host is potentially affected by the following vulnerabilities :

  - An error exists related to 'nicm.sys' and handling
    '0x143b6b' IOCTL requests that could allow arbitrary
    code execution. (CVE-2013-3956)

  - An integer overflow exists related to 'nwfs.sys' and
    handling '0x1439B' IOCTL requests that could allow
    arbitrary code execution. (CVE-2013-3697)");
  script_set_attribute(attribute:"see_also", value:"http://www.novell.com/support/kb/doc.php?id=7012497");
  script_set_attribute(attribute:"solution", value:"Apply the patch referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell Client 2 SP3 nicm.sys Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/03");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:client");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("smb_hotfixes.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

# Unless we're being paranoid, check whether the software's installed.
if (report_paranoia < 2)
  get_kb_item_or_exit("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Novell Client for Windows/DisplayName");

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Novell Client is installed - check if it's Client or Client 2 (newer)
key =  "SOFTWARE\Novell\Client\Version\ProductName";
name = get_registry_value(handle:hklm, item:key);
if (isnull(name))
  client2 = FALSE;
else
{
  client2 = TRUE;
  if ("Novell Client 2 SP2" >< name)
    sp = 2;
  if ("Novell Client 2 SP3" >< name)
    sp = 3;
}

key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Novell Client for Windows\UninstallString";
path = get_registry_value(handle:hklm, item:key);
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "Novell Client for Windows");
}

if (client2)
{
  # Clean up path
  matches = eregmatch(string:path, pattern:'^.* "([A-Za-z]:.*)\\\\ncsetup\\.dll" .*$');
  if (isnull(matches))
  {
    RegCloseKey(handle:hklm);
    close_registry();
    audit(AUDIT_UNINST, "Novell Client 2 for Windows");
  }
  path = matches[1];
}
else
{
  path = hotfix_get_systemroot();
  if (!path)
  {
    RegCloseKey(handle:hklm);
    close_registry();
    audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');
  }
}

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
if (client2)
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\acu.exe", string:path);
else
  exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\system32\drivers\nicm.sys", string:path);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
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
  audit(AUDIT_UNINST, "Novell Client for Windows");
}

vuln = FALSE;
ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver))
  audit(AUDIT_VER_FAIL, exe);

version = join(ver, sep:'.');

# New Client 2
# Checking acu.exe for New Client
if (client2)
{
  if (sp == 2)
  {
    appname = 'Novell Client 2 SP2';
    fixed = '5.0.66.6187';
  }
  else if (sp == 3)
  {
    appname = 'Novell Client 2 SP3';
    fixed = '5.0.67.405';
  }
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
    vuln = TRUE;
}
# Original/old client
else
{
  appname = 'Novell Client';
  fixed = '3.0.0.9';
  if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
    vuln = TRUE;
}

if (vuln)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Application       : ' + appname +
      '\n  File              : ' + str_replace(string:share, find:"$", replace:":", count:1) + exe +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
exit(0, appname + ", identified by the file " + str_replace(string:share, find:"$", replace:":", count:1) + exe + " having version " + version + ", is installed and not affected.");
