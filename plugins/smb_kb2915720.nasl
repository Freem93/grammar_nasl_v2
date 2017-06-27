#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71322);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2014/07/30 00:47:03 $");

  script_name(english:"KB2915720: Changes in Windows Authenticode Signature Verification");
  script_summary(english:"Checks if Windows Authenticode signature verification certificate padding check has been enabled");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has not enabled a recommended Windows
Authenticode configuration change.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has not enabled the Windows Authenticode
signature verification certificate padding check. This means
extraneous information can be included in signed binaries.

Note that Microsoft announced on July 29, 2014, that it no longer
plans to enforce the stricter signature verification behavior by
default, which would have caused previously-signed binaries to be
considered unsigned if they contained extraneous information in the
WIN_CERTIFICATE structure of the signed executable. It does, though,
remain an opt-in feature.

Note also that this plugin will report if the Windows Authenticode
signature verification has been enabled provided that the 'Report
paranoia' Global variable setting preference is set to 'Paranoid (more
false alarms)'.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/security/advisory/2915720");
  script_set_attribute(attribute:"solution", value:
"Apply the suggested actions referenced in Microsoft Security Advisory
(2915720). These actions may cause previously signed binaries to be
considered unsigned. Refer to the advisory for more information.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "Settings/ParanoidReport");
  script_require_ports(139, 445);
  exit(0);
}

include("global_settings.inc");
include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

port = kb_smb_transport();

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

key = "Software\Microsoft\Cryptography\Wintrust\Config\EnableCertPaddingCheck";
padding_check = get_registry_value(handle:hklm, item:key);

RegCloseKey(handle:hklm);
close_registry();

if (isnull(padding_check) || padding_check != "1")
{
  if (report_verbosity > 0)
  {
    report = '\n' + 'Windows Authenticode signature verification certificate padding check has not been enabled.\n';
    security_note(port:port, extra:report);
  }
  else security_note(port:port);
}
else audit(AUDIT_PATCH_INSTALLED, "Windows Authenticode signature verification certificate padding check");
