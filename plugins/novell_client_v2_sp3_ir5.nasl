#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(72348);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/02/06 02:37:08 $");

  script_cve_id("CVE-2013-3705");
  script_bugtraq_id(64484);
  script_osvdb_id(101261);

  script_name(english:"Novell Client 2 Vba32 AntiRootKit DoS");
  script_summary(english:"Checks version of acu.exe");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a client application installed that is affected by
a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Novell Client 2 installed on the remote Windows host is
SP3 prior to IR5 and is, therefore, potentially affected by an error
related to 'Vba32 AntiRootKit' and handling unsupported IOCTL
functionality.  This error could allow denial of service attacks.");
  script_set_attribute(attribute:"see_also", value:"https://www.novell.com/support/kb/doc.php?id=7014276");
  script_set_attribute(attribute:"solution", value:"Upgrade to Novell Client 2 SP3 IR5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/05");

  script_set_attribute(attribute:"cpe", value:"cpe:/a:novell:client");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

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
{
  if (isnull(get_kb_item("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/Novell Client for Windows/DisplayName")))
    audit(AUDIT_NOT_INST, "Novell Client 2");
}

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

if (isnull(name)) audit(AUDIT_NOT_INST, "Novell Client 2");
if ("Novell Client 2 SP3" >< name)
{
  appname = 'Novell Client 2 SP3 IR5';
  fixed = '5.0.73.2498';
}
else audit(AUDIT_NOT_INST, "Novell Client 2 SP3");

key =  "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Novell Client for Windows\UninstallString";
path = get_registry_value(handle:hklm, item:key);
if (isnull(path))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_NOT_INST, "Novell Client 2 for Windows");
}

# Clean up path
matches = eregmatch(string:path, pattern:'^.* "([A-Za-z]:.*)\\\\ncsetup\\.dll" .*$');
if (isnull(matches))
{
  RegCloseKey(handle:hklm);
  close_registry();
  audit(AUDIT_UNINST, "Novell Client 2 for Windows");
}
path = matches[1];

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

share = hotfix_path2share(path:path);
exe = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\acu.exe", string:path);

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
  audit(AUDIT_UNINST, "Novell Client 2 for Windows");
}

ver = GetFileVersion(handle:fh);
CloseFile(handle:fh);
NetUseDel();

if (isnull(ver)) audit(AUDIT_VER_FAIL, exe);

version = join(ver, sep:'.');

if (ver_compare(ver:version, fix:fixed, strict:FALSE) < 0)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  Application       : ' + appname +
      '\n  File              : ' + str_replace(string:share, find:"$", replace:":", count:1) + exe +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fixed +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
exit(0, appname + ", identified by the file " + str_replace(string:share, find:"$", replace:":", count:1) + exe + " having version " + version + ", is installed and not affected.");
