# @DEPRECATED@
#
# Disabled on 2014/06/12. Deprecated by smb_nt_ms14-035.nasl
#

#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74138);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2014/06/12 14:03:35 $");

  script_cve_id("CVE-2014-1770");
  script_bugtraq_id(67544);
  script_osvdb_id(107182);
  script_xref(name:"CERT", value:"239151");

  script_name(english:"Microsoft Internet Explorer 8 CMarkup Use-After-Free Remote Code Execution");
  script_summary(english:"Checks for workaround.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a version of Internet Explorer installed that is
affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host has a version of Microsoft Internet Explorer installed
that is affected by a use-after-free remote code execution
vulnerability related to the handling of CMarkup objects.");
  script_set_attribute(attribute:"see_also", value:"http://zerodayinitiative.com/advisories/ZDI-14-140/");
  # https://www.corelan.be/index.php/2014/05/22/on-cve-2014-1770-zdi-14-140-internet-explorer-8-0day/
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?b062019d");
  script_set_attribute(attribute:"solution", value:"Apply the workarounds mentioned in the CERT and ZDI advisories.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/22");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("microsoft_emet_installed.nasl", "smb_hotfixes.nasl", "microsoft_ie_esc_detect.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Use plugin #74427 (smb_nt_ms14-035.nasl) instead.");


include('audit.inc');
include('global_settings.inc');
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# if IE ESC is enabled for all users, the remote host is not vulnerable
if(get_kb_item("SMB/IE_ESC/User_Groups_Enabled"))
  exit(0, "IE Enhanced Security Configuration is enabled for all users on the remote host.");

# Only IE 8 affected
version = get_kb_item_or_exit("SMB/IE/Version");
v = split(version, sep:".", keep:FALSE);
if (int(v[0]) != 8) audit(AUDIT_INST_VER_NOT_VULN, "IE", version);

registry_init();

emet_info = '';

emet_installed = FALSE;
emet_with_ie   = FALSE;

if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed")))
  emet_installed = TRUE;

# Check if EMET is configured with IE.
# The workaround does not specifically ask to enable DEP
# but if IE is configured with EMET, dep is enabled by default.

emet_list = get_kb_list("SMB/Microsoft/EMET/*");
if (!isnull(emet_list))
{
  foreach entry (keys(emet_list))
  {
    if ("iexplore.exe" >< entry && "/dep" >< entry)
    {
      dep = get_kb_item(entry);
      if (!isnull(dep) && dep == 1)
        emet_with_ie = TRUE;
    }
  }
}

if (!emet_installed)
{
  emet_info =
  '\n  Microsoft Enhanced Mitigation Experience Toolkit (EMET) is not' +
  '\n  installed.';
}
else if (emet_installed)
{
  if (!emet_with_ie)
  {
    emet_info =
    '\n  Microsoft Enhanced Mitigation Experience Toolkit (EMET) is' +
    '\n  installed, however Internet Explorer is not configured with EMET.';
  }
}

info_user_settings = '';

# check mitigation per user
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');

if(!isnull(subkeys))
{
  foreach key (subkeys)
  {
    if ('.DEFAULT' >< key || 'Classes' >< key ||
       key =~ "^S-1-5-\d{2}$") # skip built-in accounts
      continue;

    mitigation = FALSE;

    # "Set Internet and Local intranet security zone settings to "High" to block ActiveX Controls and Active Scripting in these zones"
    key_part_intranet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\CurrentLevel';
    key_part_internet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\CurrentLevel';

    value = get_registry_value(handle:hku, item:key + key_part_intranet);
    value1 = get_registry_value(handle:hku, item:key + key_part_internet);

    if (isnull(value) && isnull(value1))
      continue;

    # 0x00012000 = 73728 = High Security
    if (!isnull(value) && !isnull(value1) &&
       value == 73728 && value1 == 73728)
      mitigation = TRUE;

    # "Configure Internet Explorer to prompt before running Active Scripting or to disable Active Scripting in the Internet and Local intranet security zone"
    key_part_intranet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\1400';
    key_part_internet = '\\SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1400';

    value = get_registry_value(handle:hku, item:key + key_part_intranet);
    value1 = get_registry_value(handle:hku, item:key + key_part_internet);

    # 1 = prompt, 3 = disable
    if (!isnull(value) && !isnull(value1) &&
       (value == 1 || value == 3) && (value1 == 1 || value1 == 3))
      mitigation = TRUE;

    if (!mitigation)
      info_user_settings += '\n    ' + key + ' (Active Scripting Enabled)';
  }
}

RegCloseKey(handle:hku);

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# check if user settings have been overridden by what is in HKLM
# note: Security_HKLM_only can be set by group policy
value = get_registry_value(handle:hklm, item:'SOFTWARE\\Policies\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Security_HKLM_only');

if (info_user_settings != '' && !isnull(value) && value == 1)
{
  mitigation = FALSE;

# "Set Internet and Local intranet security zone settings to "High" to block ActiveX Controls and Active Scripting in these zones"
  key_part_intranet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\CurrentLevel';
  key_part_internet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\CurrentLevel';

  value = get_registry_value(handle:hklm, item:key_part_intranet);
  value1 = get_registry_value(handle:hklm, item:key_part_internet);

  # 0x00012000 = 73728 = High Security
  if (!isnull(value) && !isnull(value1) &&
     value == 73728 && value1 == 73728)
    mitigation = TRUE;

  # "Configure Internet Explorer to prompt before running Active Scripting or to disable Active Scripting in the Internet and Local intranet security zone"
  key_part_intranet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\1\\1400';
  key_part_internet = 'SOFTWARE\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\\Zones\\3\\1400';

  value = get_registry_value(handle:hklm, item:key_part_intranet);
  value1 = get_registry_value(handle:hklm, item:key_part_internet);

  # 1 = prompt, 3 = disable
  if (!isnull(value) && !isnull(value1) &&
     (value == 1 || value == 3) && (value1 == 1 || value1 == 3))
    mitigation = TRUE;

  if (mitigation)
    info_user_settings = '';
}

RegCloseKey(handle:hklm);

close_registry();

if (info_user_settings != '')
{
  port = kb_smb_transport();

  if (report_verbosity > 0)
  {
    if (emet_info != '')
      report =
      '\n  The following users have vulnerable IE settings :' + info_user_settings + '\n' + emet_info + '\n';
    else
      report =
      '\n  The following users have vulnerable IE settings :' + info_user_settings + '\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since a workaround has been applied.");
