#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71324);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/06/09 20:36:07 $");

  script_name(english:"MS KB2871690: Update to Revoke Non-compliant UEFI Modules");
  script_summary(english:"Checks the timestamp of Dbxupdate.bin");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is missing an update that revokes the digital
signatures for several UEFI modules.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing Microsoft KB2871690, an update that revokes
the digital signatures of nine third-party UEFI modules.  This update
prevents the modules from being loaded on systems where UEFI Secure Boot
is enabled.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2871690");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 8 and Server 2012.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated");
  script_require_ports(139, 445);

  exit(0);
}

include("datetime.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
if (hotfix_check_sp_range(win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

name   = kb_smb_name();
port   = kb_smb_transport();
if (!get_port_state(port)) audit(AUDIT_PORT_CLOSED, port);
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SYSTEM\CurrentControlSet\Control\SecureBoot\State";
res = get_registry_value(handle:hklm, item:key);


RegCloseKey(handle:hklm);
NetUseDel(close:FALSE);

if (isnull(res) || res == 0)
{
  NetUseDel();
  exit(0, 'The host is not affected because UEFI Secure Boot is not enabled.');
}

# Only check the timestamp if report_paranoia is set to paranoid.
if (report_paranoia < 2)
{
  NetUseDel();
  audit(AUDIT_PARANOID);
}

windir = hotfix_get_systemroot();
if (isnull(windir))
{
  NetUseDel();
  exit(1, "Failed to determine the location of %windir%");
}

share = hotfix_path2share(path:windir);
rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

bin = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\System32\SecureBootUpdates\dbxupdate.bin", string:windir);
file = FindFirstFile(pattern:bin);
timestamp = file[3][2];
NetUseDel();

if (isnull(timestamp))
  exit(1, 'Failed to get the timestamp of ' + windir + "\System32\SecureBootUpdates\dbxupdate.bin");

if (int(timestamp) < 1383350400)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  File            : ' + windir + "\System32\SecureBootUpdates\dbxupdate.bin" +
      '\n  File timestamp  : ' + strftime(timestamp) +
      '\n  Fixed timestamp : ' + strftime(1383350400) + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
audit(AUDIT_HOST_NOT, 'affected');
