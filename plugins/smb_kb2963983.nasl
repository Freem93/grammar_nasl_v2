#
# (C) Tenable Network Security, Inc.
#

# @DEPRECATED@
#
# Disabled on 2014/05/01.  Deprecated by smb_nt_ms14-021.nasl
#

include("compat.inc");

if (description)
{
  script_id(73739);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/05/18 04:28:24 $");

  script_cve_id("CVE-2014-1776");
  script_bugtraq_id(67075);
  script_osvdb_id(106311);
  script_xref(name:"CERT", value:"222929");

  script_name(english:"MS KB2963983: Vulnerability in Internet Explorer Could Allow Remote Code Execution");
  script_summary(english:"Checks if workarounds referenced in KB article have been applied.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing one of the workarounds referenced in
Microsoft Security Advisory 2963983.

The remote Internet Explorer install is affected by an unspecified
use-after-free vulnerability related to the VML and Flash components.
By exploiting this flaw, a remote, unauthenticated attacker could
execute arbitrary code on the remote host subject to the privileges of
the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-US/library/security/2963983");
  # http://blogs.technet.com/b/srd/archive/2014/04/26/more-details-about-security-advisory-2963983-ie-0day.aspx
  script_set_attribute(attribute:"see_also",value:"http://www.nessus.org/u?671b0a2a");
  script_set_attribute(attribute:"solution", value:
"Apply the IE settings and workarounds suggested by Microsoft in
security advisory 2963983.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/04/28");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("microsoft_emet_installed.nasl", "smb_hotfixes.nasl", "microsoft_ie_esc_detect.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "SMB/IE/Version");
  script_require_ports(139, 445);
  exit(0);
}

# Deprecated
exit(0, "This plugin has been deprecated.  Use plugin #73805 (smb_nt_ms14-021.nasl) instead.");

include('audit.inc');
include('global_settings.inc');
include("smb_hotfixes.inc");
include("misc_func.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");

ACCESS_DENIED_ACE_TYPE = 1;

#
# @return DACL associated with 'fh'
##
function get_dacl()
{
  local_var fh, sd, dacl;
  fh = _FCT_ANON_ARGS[0];

  sd = GetSecurityInfo(handle:fh, level:DACL_SECURITY_INFORMATION);

  if (isnull(sd))
    return NULL;

  dacl = sd[3];
  if (isnull(dacl))
    return NULL;

  dacl = parse_pdacl(blob:dacl);
  if (isnull(dacl))
    return NULL;

  return dacl;
}

if (hotfix_check_sp_range(vista:'2', win2003:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

ie_epm_avail = FALSE;
version = get_kb_item_or_exit("SMB/IE/Version");
v = split(version, sep:".", keep:FALSE);
if (int(v[0]) == 11 || int(v[0]) == 10) ie_epm_avail = TRUE;

# server core not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# if IE ESC is enabled for all users, the remote host is not vulnerable
if(get_kb_item("SMB/IE_ESC/User_Groups_Enabled"))
  exit(0, "IE Enhanced Security Configuration is enabled for all users on the remote host.");

registry_init();

vuln = FALSE;

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
value = get_registry_value(handle:hklm, item:"SOFTWARE\Classes\PeerDraw.PeerDraw.1\CLSID\");

RegCloseKey(handle:hklm);

# this checks for vgx.dll mitigations
# Microsoft suggests either unregistering the DLL or
# setting a deny permission for the 'everyone' group on the file
clsid = '{10072CEC-8CC1-11D1-986E-00A0C955B42E}';
if(value == clsid)
{
  vuln = TRUE;

  # check permissions
  NetUseDel(close:FALSE);

  commonprogramfiles = hotfix_get_commonfilesdir();
  if (isnull(commonprogramfiles))
    exit(1, "Failed to determine the location of %commonprogramfiles%.");

  vuln_file = commonprogramfiles + "\Microsoft Shared\VGX\vgx.dll";

  obj = ereg_replace(pattern:"^[A-Za-z]:(.*)", replace:"\1", string:vuln_file);
  share = hotfix_path2share(path:vuln_file);

  rc = NetUseAdd(share:share);

  if(!rc)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  fh = CreateFile(
    file:obj,
    desired_access:STANDARD_RIGHTS_READ,
    file_attributes:FILE_ATTRIBUTE_NORMAL,
    share_mode:FILE_SHARE_READ,
    create_disposition:OPEN_EXISTING
  );

  if(isnull(fh))
  {
    NetUseDel();
    exit(1, "Unable to read permission on 'vgx.dll'.");
  }

  dacls = get_dacl(fh);
  CloseFile(handle:fh);

  ace = NULL;
  if(!isnull(dacls))
    ace = parse_dacl(blob:dacls[0]);

  if(!isnull(ace))
  {
    rights = ace[0];
    type = ace[3];
    sid = sid2string(sid:ace[1]);
    # workaround is to deny access to everyone
    if (sid == '1-1-0' && rights & FILE_WRITE_DATA)
    {
      if (type == ACCESS_DENIED_ACE_TYPE)
        vuln = FALSE;
    }
  }
}

# close in case we exit
close_registry();

if(!vuln)
  exit(0, "The remote host has a workaround applied preventing access to 'vgx.dll'");

emet_info = '';

emet_installed = FALSE;
emet_with_ie   = FALSE;

# EMET 3.0 does not mitigate this issue
# 4.1 needs to be installed to prevent exploitation
emet_bad_version = FALSE;

if (!isnull(get_kb_item("SMB/Microsoft/EMET/Installed"))) emet_installed = TRUE;

if(emet_installed)
{
  emet_version = get_kb_item_or_exit("SMB/Microsoft/EMET/Version");
  if(ver_compare(ver:emet_version, fix:"4.1", strict:FALSE) == -1)
    emet_bad_version = TRUE;
}

# Check if EMET is configured with IE.
# The workaround does not specifically ask to enable DEP
# but if IE is configured with EMET, dep is enabled by default.

if(!emet_bad_version)
{
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
  if(emet_bad_version)
  {
    emet_info =
      '\n  The version of Microsoft Enhanced Mitigation Experience Toolkit (EMET)' +
      '\n  installed does not mitigate the vulnerability.';
  }
}

if(emet_installed && emet_with_ie && !emet_bad_version)
  exit(0, "Enhanced Mitigation Toolkit is installed and configured with IE to prevent the vulnerability.");

info_user_settings = '';

registry_init();

# check mitigation per user
hku = registry_hive_connect(hive:HKEY_USERS, exit_on_fail:TRUE);
subkeys = get_registry_subkeys(handle:hku, key:'');

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

  # check for IE enhanced protected mode configuration
  if(ie_epm_avail)
  {
    isolation_key = "\Software\Microsoft\Internet Explorer\Main\Isolation";
    value = get_registry_value(handle:hku, item:key + isolation_key);

    if(value == "PMEM")
    {
      isolation_key_64 = "\Software\Microsoft\Internet Explorer\Main\Isolation64Bit";
      value = get_registry_value(handle:hku, item:key + isolation_key_64);
      # if "Enable 64-bit processes for Enhanced Protected Mode" is an available setting in IE,
      # this registry will be initialized to 0 when "Enable Enhance Protected Mode" is set,
      # or set to 1 if both boxes are check.
      if(isnull(value) || value == 1)
        mitigation = TRUE;
    }
  }

  # 1 = prompt, 3 = disable
  if (!isnull(value) && !isnull(value1) &&
     (value == 1 || value == 3) && (value1 == 1 || value1 == 3))
    mitigation = TRUE;

  if (!mitigation)
  {
    # we check enhanced protected mode setting in IE 11 / 10 only
    if(ie_epm_avail)
      info_user_settings += '\n    ' + key + ' (Active Scripting Enabled and Enhanced Protected Mode Disabled)';
    else info_user_settings += '\n    ' + key + ' (Active Scripting Enabled)';
  }
}

RegCloseKey(handle:hku);

hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# check for Group Policy Enhanced Protected Mode Mitigation
if(ie_epm_avail)
{
  value = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\Internet Explorer\Main\Isolation");
  if(value == "PMEM")
  {
    value = get_registry_value(handle:hklm, item:"SOFTWARE\Policies\Microsoft\Internet Explorer\Main\Isolation64Bit");
    # if "Enable 64-bit processes for Enhanced Protected Mode" is an available setting in IE,
    # this registry will be initialized to 0 when "Enable Enhance Protected Mode" is set,
    # or set to 1 if both boxes are check.
    if(isnull(value) || value == 1)
    {
      RegCloseKey(handle:hklm);
      close_registry();
      exit(0, "IE 11 Enhanced Protected Mode Mitigation is enabled.");
    }
  }
}

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
      '\n' + 'The following users have vulnerable IE settings :' + info_user_settings + '\n' + emet_info + '\n';
    else
      report =
      '\n' + 'The following users have vulnerable IE settings :' + info_user_settings + '\n';

    report +=
    '\n' + 'Additionally, the remote host is missing a workaround to' +
    '\n' + 'restrict access to \'vgx.dll\'\n';

    security_hole(port:port, extra:report);
  }
  else security_hole(port);
  exit(0);
}
else exit(0, "The host is not affected since an IE setting workaround has been applied.");
