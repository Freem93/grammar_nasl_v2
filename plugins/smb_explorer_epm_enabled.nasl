#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76056);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/06/14 00:24:17 $");

  script_name(english:"Microsoft Internet Explorer Enhanced Protection Mode (EPM) Detection");
  script_summary(english:"Checks Enhanced Protection Mode (EPM) status.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has Enhanced Protection Mode (EPM) for Microsoft
Internet Explorer enabled.");
  script_set_attribute(attribute:"description", value:
"The remote host has Enhanced Protection Mode (EPM) enabled for the
Microsoft Internet Explorer web browser.

Enhanced Protection Mode (EPM) is an added layer of protection first
added in Microsoft Internet Explorer version 10 that provides a
security feature set that includes :

  - individual browser tabs can be run in 64-bit mode,
    increasing the effectiveness of Address Space Layout
    Randomization (ASLR)

  - better access protection for files via a broker process

  - untrusted web pages cannot access domain credentials

Note that Microsoft Internet Explorer running in 'Metro style' uses
Enhanced Protected Mode by default.");
  # http://blogs.msdn.com/b/ie/archive/2012/03/14/enhanced-protected-mode.aspx
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?96bc4254");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/WindowsVersion", "SMB/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}

include("audit.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

winver = get_kb_item_or_exit("SMB/WindowsVersion");
if (ver_compare(ver:winver, fix:'6.1', strict:FALSE) < 0)
  exit(0, "The host runs a version of Windows before 7 / 2008 R2 and, thus does not support Enhanced Protection Mode.");

# server core not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# Only x64
arch = get_kb_item_or_exit("SMB/ARCH");
if (arch != "x64") audit(AUDIT_ARCH_NOT, "x64", arch);

version = get_kb_item_or_exit("SMB/IE/Version");
v = split(version, sep:".", keep:FALSE);
if (int(v[0]) != 11 && int(v[0]) != 10) audit(AUDIT_NOT_INST, "An EPM compatible IE version");

info_user_settings = '';
info_gpo_settings = '';

registry_init();

# check mitigation per user
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');

if (isnull(subkeys))
{
  RegCloseKey(handle:hku);
  close_registry();
  audit(AUDIT_FN_FAIL, 'get_registry_subkeys', "NULL from HKEY_USERS hive");
}

foreach key (subkeys)
{
  if ('.DEFAULT' >< key || 'Classes' >< key ||
     key =~ "^S-1-5-\d{2}$") # skip built-in accounts
    continue;

  isolation_key = "\Software\Microsoft\Internet Explorer\Main\Isolation";
  value = get_registry_value(handle:hku, item:key + isolation_key);

  if(
    value == "PMEM"
    ||
    # Win 8.1/2012 R2 omit this key
    # however EPM *is* enabled.
    # Using only '6.3' for now - it is
    # not clear how MS will proceed.
    (isnull(value) && win_ver == "6.3")
  )
  {
    replace_kb_item(name:"SMB/internet_explorer_EPM/per_user_enabled", value:TRUE);
    info_user_settings +=
      '\n    ' +
      key +
      '\n        - Enhanced Protected Mode is enabled';
    isolation_key_64 = "\Software\Microsoft\Internet Explorer\Main\Isolation64Bit";
    value = get_registry_value(handle:hku, item:key + isolation_key_64);
    # if "Enable 64-bit processes for Enhanced Protected Mode" is an available setting in IE,
    # this registry will be initialized to 0 when "Enable Enhance Protected Mode" is set,
    # or set to 1 if both boxes are check.
    if(
      value == 1
      ||
      (isnull(value) && win_ver == "6.3") # Win 8.1/2012 R2
    )
    {
      info_user_settings += '\n        - 64-bit processes for Enhanced Protected Mode is enabled';
      replace_kb_item(name:"SMB/internet_explorer_EPM/per_user_enabled_64bit_procs", value:TRUE);
    }
    info_user_settings += '\n';
  }
}
RegCloseKey(handle:hku);

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# check for Group Policy Enhanced Protected Mode Mitigation
value = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Policies\Microsoft\Internet Explorer\Main\Isolation"
);

if(
  value == "PMEM"
  ||
  (isnull(value) && win_ver == "6.3") # Win 8.1/2012 R2
)
{
  set_kb_item(name:"SMB/internet_explorer_EPM/gpo_enabled", value:TRUE);
  info_gpo_settings =
    '\n' +
    'Enhanced Protected Mode for IE has been enabled via Group Policy configuration.' +
    '\n';
  value = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit");
  # if "Enable 64-bit processes for Enhanced Protected Mode" is an available setting in IE,
  # this registry will be initialized to 0 when "Enable Enhance Protected Mode" is set,
  # or set to 1 if both boxes are check.
  if(
    value == 1
    ||
    (isnull(value) && win_ver == "6.3") # Win 8.1/2012 R2
  )
  {
    info_gpo_settings +=
      '        - 64-bit processes for Enhanced Protected Mode is enabled';
    set_kb_item(name:"SMB/internet_explorer_EPM/gpo_enabled_64bit_procs", value:TRUE);
  }
}
RegCloseKey(handle:hklm);
close_registry();

if (info_user_settings != '' || info_gpo_settings != '')
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    if (info_user_settings != '')
    {
      report =
        '\n' + 'The following users have Enhanced Protection Mode IE settings :' +
        '\n' +
        info_user_settings;
    }

    # GPO
    if (info_gpo_settings != '')
      report += info_gpo_settings;

    security_note(port:port, extra:report);
  }
  else security_note(port);
}
else exit(0, "The remote host does not have Enhanced Protection Mode enabled for Microsoft Internet Explorer.");
