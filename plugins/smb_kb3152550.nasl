#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90511);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/04/13 19:55:05 $");

  script_name(english:"MS KB3152550: Update to Improve Wireless Mouse Input Filtering");
  script_summary(english:"Checks the version of WirelessKeyboardFilter.sys and WirelessDevice.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing an update to wireless mouse input
filtering.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing an update to the wireless mouse
input filtering functionality. The missing update enhances security
by filtering out QWERTY key packets in keystroke communications issued
when receiving communication from USB wireless dongles. The update
resolves a vulnerability that allows a local attacker in the physical
proximity of the wireless mouse range to inject keyboard HID packets
into Microsoft wireless mouse devices through the use of USB dongles.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/3152550");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 8.1, and 10.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/01/23");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"in_the_news", value:"true");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

prod_name = get_kb_item_or_exit("SMB/ProductName");
if ("2008" >< prod_name || "2012" >< prod_name) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

systemroot = hotfix_get_systemroot();
if (empty_or_null(systemroot)) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port   = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(!smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

base = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\System32\DriverStore\FileRepository", string:systemroot);
keyboard_files = list_dir(basedir:base, level:0, dir_pat:"wirelesskeyboardfilter.inf_", file_pat:"^WirelessKeyboardFilter\.sys$", max_recurse:1);
device_files = list_dir(basedir:base, level:0, dir_pat:"wirelessdevice.inf_", file_pat:"^WirelessDevice\.dll$", max_recurse:1);
NetUseDel();

# If the files don't exist, report missing update
if (empty_or_null(keyboard_files) && empty_or_null(device_files))
{
  report = 'Nessus has determined that the remote Windows host is missing files\n' +
           'that are created upon installation of the update corresponding to\n' +
           'Microsoft Security Advisory 3152550.';
  security_report_v4(severity:SECURITY_NOTE, port:0, extra:report);
  hotfix_check_fversion_end();
  exit(0);
}

vuln = FALSE;
kb = "3152550";

if (!empty_or_null(keyboard_files))
{
  file = 'WirelessKeyboardFilter.sys';
  fix = "1.0.102.0";
  foreach dir (keyboard_files)
  {
    dir = dir - "\Windows" - file;
    if (
      hotfix_is_vulnerable(os:"10",  sp:0, file:file, version:fix, dir:dir, kb:kb) ||
      hotfix_is_vulnerable(os:"6.3", sp:0, file:file, version:fix, dir:dir, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:file, version:fix, dir:dir, kb:kb)
    ) vuln = TRUE;
  }
}

if (!empty_or_null(device_files))
{
  file = 'WirelessDevice.dll';
  fix = "1.0.102.0";
  foreach dir (device_files)
  {
    dir = dir - "\Windows" - file;
    if (
      hotfix_is_vulnerable(os:"10",  sp:0, file:file, version:fix, dir:dir, kb:kb) ||
      hotfix_is_vulnerable(os:"6.3", sp:0, file:file, version:fix, dir:dir, kb:kb) ||
      hotfix_is_vulnerable(os:"6.1", sp:1, file:file, version:fix, dir:dir, kb:kb)
    ) vuln = TRUE;
  }
}

if (vuln)
{
  hotfix_security_note();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
