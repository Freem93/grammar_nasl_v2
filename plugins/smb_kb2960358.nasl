#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73992);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/02/18 20:42:24 $");

  script_name(english:"MS KB2960358: Update for Disabling RC4 in .NET TLS");
  script_summary(english:"Checks version of .NET Framework files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a deprecated, weak encryption cipher available.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing an update for disabling the weak RC4 cipher
suite in .NET TLS.

Note that even though .NET Framework 4.6 itself is not affected, any
Framework 4.5, 4.5.1, or 4.5.2 application that runs on a system that
has 4.6 installed is affected.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/2960358");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of security updates for the .NET
Framework on Windows 7, 2008 R2, 8, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("smb_reg_query.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");

my_os = get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
my_sp = get_kb_item("SMB/CSDVersion");
if (isnull(my_sp)) my_sp = 0;

if (hotfix_check_sp_range(win10:'0', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

bulletin = "KB2960358";
vuln = 0;

# Determine if .NET 3.5, 4.5, 4.5.1, 4.5.2, or 4.6 is installed
dotnet_35_installed = FALSE;
dotnet_452_installed = FALSE;
dotnet_451_installed = FALSE;
dotnet_45_installed  = FALSE;
dotnet_46_installed = FALSE;

count = get_install_count(app_name:'Microsoft .NET Framework');
if (count > 0)
{
  installs = get_installs(app_name:'Microsoft .NET Framework');
  foreach install(installs[1])
  { 
    ver = install["version"];
    if (ver == "3.5") dotnet_35_installed = TRUE;
    if (ver == "4.5") dotnet_45_installed = TRUE;
    if (ver == "4.5.1") dotnet_451_installed = TRUE;
    if (ver == "4.5.2") dotnet_452_installed = TRUE;
    if (ver == "4.6") dotnet_46_installed = TRUE;
  }
}
arch = get_kb_item("SMB/ARCH");
is_64bit = arch == "x64";

# 2954853
# .NET Framework 4.5.2 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
# Registry only fix
# HKLM\SOFTWARE\Microsoft\Updates\Microsoft .NET Framework 4.5.2\KB2954853\ThisVersionInstalled = "Y"
missing = 0;
if ("6.1" >< my_os && my_sp == 1)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  net45 = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Updates\Microsoft .NET Framework 4.5.2\");
  if (!isnull(net45))
  {
    kb_installed = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\Updates\Microsoft .NET Framework 4.5.2\KB2954853\ThisVersionInstalled");
    if (isnull(kb_installed) || kb_installed != "Y")
      missing++;
  }
  RegCloseKey(handle:hklm);
  close_registry();
}
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2954853");
vuln += missing;

# Win10 and .NET 3.5
missing = 0;
need_32bit_key = FALSE;
need_64bit_key = FALSE;
if("10" >< my_os && dotnet_35_installed)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  if(is_64bit) {
    sch_keys = make_list("SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto", "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto");
    wanted_values = get_registry_values(handle: hklm, items:sch_keys);
    if(wanted_values["SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto"] != 1)
    {
      need_32bit_key = TRUE;
      missing++;
    }
    if(wanted_values["SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto"] != 1)
    {
      need_64bit_key = TRUE;
      missing++;
    }
  } else {
    sch_key = "SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto";
    wanted_value = get_registry_value(handle: hklm, item:sch_key);
    if(wanted_value != 1)
    {
      need_32bit_key = TRUE;
      missing++;
    }
  }
  RegCloseKey(handle:hklm);
  close_registry();
}
if(missing > 0) {
  registry_fix_message = "The following registry values have not been
set to 1 :";
  if(need_32bit_key)
  {
    registry_fix_message += '\n' + "HKLM\SOFTWARE\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto";
  }
  if(need_64bit_key) {
    registry_fix_message += '\n' + "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v2.0.50727\SchUseStrongCrypto";
  }
  registry_fix_message += '\n';
  hotfix_add_report(registry_fix_message, bulletin:2960358);
}
vuln += missing;

# .NET 4.5{.1,2}
missing = 0;
need_32bit_key = FALSE;
need_64bit_key = FALSE;
if(dotnet_46_installed && "10" >!< my_os)
{
  registry_init();
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  if(is_64bit) {
    sch_keys = make_list("SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto", "SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto");
    wanted_values = get_registry_values(handle: hklm, items:sch_keys);
    if(wanted_values["SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto"] != 1)
    {
      need_32bit_key = TRUE;
      missing++;
    }
    if(wanted_values["SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto"] != 1)
    {
      need_64bit_key = TRUE;
      missing++;
    }
  } else {
    sch_key = "SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto";
    wanted_value = get_registry_value(handle: hklm, item:sch_key);
    if(wanted_value != 1)
    {
      need_32bit_key = TRUE;
      missing++;
    }
  }
  RegCloseKey(handle:hklm);
  close_registry();
}
if(missing > 0) {
  registry_fix_message = '\nThe following registry values have not been
set to 1 :';
  if(need_32bit_key)
  {
    registry_fix_message += '\n' + "HKLM\SOFTWARE\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto";
  }
  if(need_64bit_key) {
    registry_fix_message += '\n' + "HKLM\SOFTWARE\Wow6432Node\Microsoft\.NETFramework\v4.0.30319\SchUseStrongCrypto";
  }
  registry_fix_message += '\n';
  hotfix_add_report(registry_fix_message, bulletin:2960358);
}
vuln += missing;

# 2898850
# .NET Framework 4.5.1 and the .NET Framework 4.5.2 on Windows 8.1, Windows RT 8.1, and Windows Server 2012 R2
# system.dll  4.0.30319.34111
# system.dll  4.0.30319.36118
# ARM
# system.dll  4.0.30319.34111
missing = 0;
missing += hotfix_is_vulnerable(os:"6.3", file:"System.dll", version:"4.0.30319.34111", min_version:"4.0.30319.34000", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.3", file:"System.dll", version:"4.0.30319.36118", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898850");
vuln += missing;

# 2898849
# .NET Framework 4.5, the .NET Framework 4.5.1, and the .NET Framework 4.5.2 on Windows 8, Windows RT, and Windows Server 2012
# system.dll  4.0.30319.34111
# system.dll  4.0.30319.36113
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", file:"System.dll", version:"4.0.30319.34111", min_version:"4.0.30319.34000", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.2", file:"System.dll", version:"4.0.30319.36113", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898849");
vuln += missing;

# 2938782
#  .NET Framework 4.5 and the .NET Framework 4.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
# System.dll  4.0.30319.34114
# System.dll  4.0.30319.36117
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.34114", min_version:"4.0.30319.34000", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.36117", min_version:"4.0.30319.36000", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2938782");
vuln += missing;

# 2938780
# .NET Framework 4 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
# System.dll  4.0.30319.1024
# System.dll  4.0.30319.2038
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.1024", min_version:"4.0.30319.0", dir:"\Microsoft.NET\Framework\v4.0.30319");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"System.dll", version:"4.0.30319.2038", min_version:"4.0.30319.2000", dir:"\Microsoft.NET\Framework\v4.0.30319");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2938780");
vuln += missing;

# 2898851
# .NET Framework 3.5.1 on Windows 7 Service Pack 1 and Windows Server 2008 R2 Service Pack 1
# system.dll  2.0.50727.5484
# system.dll  2.0.50727.7058
missing = 0;
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"2.0.50727.5484", min_version:"2.0.50727.4000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.1", sp:1, file:"system.dll", version:"2.0.50727.7058", min_version:"2.0.50727.5600", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898851");
vuln += missing;

# 2898845
#  .NET Framework 3.5 on Windows 8 and Windows Server 2012
# system.dll  2.0.50727.6417
# system.dll  2.0.50727.7058
missing = 0;
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"2.0.50727.6417", min_version:"2.0.50727.6000", dir:"\Microsoft.NET\Framework\v2.0.50727");
missing += hotfix_is_vulnerable(os:"6.2", sp:0, file:"system.dll", version:"2.0.50727.7058", min_version:"2.0.50727.7000", dir:"\Microsoft.NET\Framework\v2.0.50727");
if (missing > 0) hotfix_add_report(bulletin:bulletin, kb:"2898845");
vuln += missing;

if (vuln > 0)
{
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
