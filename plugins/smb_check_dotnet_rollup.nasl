#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99364);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_name(english:"Microsoft .NET Security Rollup Enumeration");
  script_summary(english:"Enumerates installed Microsoft .NET security rollups.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates installed Microsoft .NET security rollups.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the Microsoft .NET security rollups
installed on the remote Windows host.");
  # https://blogs.msdn.microsoft.com/dotnet/2016/10/11/net-framework-monthly-rollups-explained/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?662e30c9");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/14");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","wmi_enum_qfes.nbin", "microsoft_net_framework_installed.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion", "installed_sw/Microsoft .NET Framework");
  script_require_ports(139, 445);
  script_timeout(30*60);

  exit(0);
}

include("audit.inc");
include("install_func.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

kb_base = "smb_dotnet_rollup/";
app = 'Microsoft .NET Framework';
installs = get_installs(app_name:app, exit_if_not_found:TRUE);

# in order from latest to earliest
rollup_dates = make_list(
  "04_2017",
  "05_2017"
);
# .NET rollups
rollup_patches = {
  # April 2017
  "04_2017" : [
        # Vista SP2 / 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4014561, "sec": 4014571}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36387"}, {"cum": 4014559, "sec": 4014566}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014553, "sec": 4014558}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4014565, "sec": 4014573}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36388"}, {"cum": 4014559, "sec": 4014566}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014553, "sec": 4014558}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014553, "sec": 4014558}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4014547, "sec": 4014552}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.management.dll", "version": "2.0.50727.8758"}, {"cum": 4014563, "sec":4014572}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36386"}, {"cum": 4014557, "sec": 4014564}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014548, "sec": 4014560}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014548, "sec": 4014560}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4014545, "sec": 4014549}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "System.management.dll", "version": "2.0.50727.8758"}, {"cum": 4014567, "sec": 4014574}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.0.30319.36386"}, {"cum": 4014555, "sec": 4014562}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014551, "sec": 4014556}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4014551, "sec": 4014556}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4014546, "sec": 4014550}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4015221}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4015221}],
        # Windows 10 1511
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4015219}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1098.0"}, {"cum": 4015219}],
        # Windows 10 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8758"}, {"cum": 4015217}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.6.1646.0"}, {"cum": 4015217}],
        # Windows 10 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "Wminet_utils.dll", "version": "2.0.50727.8792"}, {"cum": 4015583}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "Wminet_utils.dll", "version": "4.7.2092.0"}, {"cum": 4015583}]
 ],
  # May 2017
  "05_2017" : [
        # 2008 Server SP2
        [{".net_version":"2.0.50727", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019115, "sec": 4019109}],
        [{".net_version":"4.5.2", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36392"}, {"cum": 4019115, "sec": 4019109}],
        [{".net_version":"4.6", "os":'6.0', "sp":2, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019115, "sec": 4019109}],
        # Windows 7 SP1 / Server 2008 R2 SP1
        [{".net_version":"3.5.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.5.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36392"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.6", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.6.1", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019112, "sec": 4019108}],
        [{".net_version":"4.6.2", "os":'6.1', "sp":1, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019112, "sec": 4019108}],
        # Server 2012
        [{".net_version":"3.5", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.5.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36389"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.6", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.6.1", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019113, "sec": 4019110}],
        [{".net_version":"4.6.2", "os":'6.2', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019113, "sec": 4019110}],
        # Windows 8.1 / Server 2012 R2
        [{".net_version":"3.5", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.5.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.0.30319.36389"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.6", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.6.1", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019114, "sec": 4019111}],
        [{".net_version":"4.6.2", "os":'6.3', "sp":0, "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019114, "sec": 4019111}],
        # Windows 10 RTM (10240)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019474}],
        [{".net_version":"4.6", "os":'10', "sp":0, "os_build": "10240", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019474}],
        # Windows 10 1511
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019473}],
        [{".net_version":"4.6.1", "os":'10', "sp":0, "os_build": "10586", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1099.0"}, {"cum": 4019473}],
        # Windows 10 1607 Anniversary Update (14393) / Server 2016
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8759"}, {"cum": 4019472}],
        [{".net_version":"4.6.2", "os":'10', "sp":0, "os_build": "14393", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.6.1647.0"}, {"cum": 4019472}],
        # Windows 10 1703 Creator's Update (15063)
        [{".net_version":"3.5", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v2.0.50727", "file": "system.dll", "version": "2.0.50727.8793"}, {"cum": 4016871}],
        [{".net_version":"4.7", "os":'10', "sp":0, "os_build": "15063", "path":"\Microsoft.NET\Framework\v4.0.30319", "file": "system.dll", "version": "4.7.2093.0"}, {"cum": 4016871}]
 ]
};

global_var registry_kbs;

function installed_ver(ver)
{
  local_var install;
  foreach install (installs[1])
  {
    if (install['version'] == ver) return TRUE;
  }
  return FALSE;
}

function is_patched(file, version, path, min_version, bulletin, kb, product, channel, channel_product, channel_version, rollup, dotnet_ver)
{
  local_var r, ver_report, report_text;

  local_var systemroot = hotfix_get_systemroot();
  if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

  r = hotfix_check_fversion(file:file, version:version, path:systemroot+path, min_version:min_version, bulletin:bulletin, kb:kb, product:product, channel:channel, channel_product:channel_product, channel_version:channel_version, rollup_check:rollup);

  if ( r == HCF_OLDER)
  {
    ver_report = hotfix_get_report();
    if (!empty_or_null(ver_report))
    {
      report_text = strstr(ver_report, rollup);
      if (!isnull(report_text))
      {
        # Remove rollup date and format the output for reporting
        report_text = report_text - rollup;
        report_text = report_text - '  - ';
        set_kb_item(name:kb_base+"version_report/"+rollup+"/"+dotnet_ver,value:report_text);
        hcf_report = '';
      }
    }
    return 0;
  }
  else
  {
    return 1;
  }
}

function kb_installed()
{
  var kb;
  kb = "KB" + _FCT_ANON_ARGS[0];
  if(registry_kbs[kb] || get_kb_item("WMI/Installed/Hotfix/" + kb))
    return TRUE;
}

registry_kbs = make_array();

registry_init();

# only pull from registry if we can't get kb hotfix info from WMI
if(!get_kb_item("SMB/WMI/Available") || isnull(get_kb_list("WMI/Installed/Hotfix/*")))
{
  hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
  packages = get_registry_subkeys(handle:hklm, key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\Packages");

  foreach package (packages)
  {
    item = pregmatch(pattern:"[^A-Za-z](KB\d{5,})([^\d]|$)", string:package);
    if (!empty_or_null(item[1]))
      registry_kbs[item[1]] = TRUE;
  }
  RegCloseKey(handle:hklm);
}

close_registry(close:FALSE);

report = '';
latest_eff = '';
cur_date = '0.0';
last_date = '0.0';
latest_file = '';
latest_ver = '';
kb_str = '';
systemroot = hotfix_get_systemroot();

latest = make_nested_array();
foreach rollup_date (rollup_dates)
{
  patch_checks = rollup_patches[rollup_date];

  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");

  if ( my_sp )
  {
    my_sp = preg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  foreach patch_check (patch_checks)
  {
    file_check = patch_check[0];
    # we only care about checking installed versions
    dotnet_ver = file_check[".net_version"];
    if (!installed_ver(ver:dotnet_ver)) continue;

    # skip over irrelevant patches
    if ( file_check["os"] >!< my_os ) continue;
    if ( !isnull(file_check["sp"]) && my_sp != file_check["sp"] ) continue;
    if ( !isnull(file_check["arch"]) && my_arch != file_check["arch"] ) continue;
    if ( !isnull(file_check["os_build"]) && my_os_build != file_check["os_build"] ) continue;

    this_kb_base = kb_base+rollup_date+"/"+dotnet_ver+"/";
    if(is_patched(file:file_check["file"],
                  version:file_check["version"],
                  path:file_check["path"],
                  rollup:rollup_date,
                  dotnet_ver:dotnet_ver))
    # patched
    {
      kb_list = patch_check[1];

      if(empty_or_null(latest[dotnet_ver]))
      {
        latest[dotnet_ver] = make_array();
        latest[dotnet_ver]['eff'] = rollup_date;
      }

      latest[dotnet_ver]['kb_str'] =  kb_list["cum"];
      if(kb_list['sec']) latest[dotnet_ver]['kb_str'] += ", " + kb_list['sec'];
      if(kb_list['pre']) latest[dotnet_ver]['kb_str'] += ", " + kb_list['pre'];

      cur_date = split(rollup_date, sep:"_", keep:FALSE);
      cur_date = cur_date[1] + "." + cur_date[0];
      last_date = split(latest[dotnet_ver]['eff'], sep:"_", keep:FALSE);
      last_date = last_date[1] + "." + last_date[0];

      if(ver_compare(ver:cur_date, fix:latest[dotnet_ver]['eff']) >=0 )
      {
        latest[dotnet_ver]['eff'] = rollup_date;
        latest[dotnet_ver]['file_name'] = systemroot + file_check["path"] + "\" + file_check["file"];
        latest[dotnet_ver]['file_ver'] = file_check["version"];
      }

      set_kb_item(name:this_kb_base, value:1);
      set_kb_item(name:this_kb_base+"file", value:latest[dotnet_ver]['file_name']);
      set_kb_item(name:this_kb_base+"file_ver", value:latest[dotnet_ver]['file_ver']);
    }
    else
    {
      set_kb_item(name:this_kb_base+"not_inst/cum", value:patch_check[1]["cum"]);
    }
  }
}

# cleanup connection
NetUseDel();

set_kb_item(name:"smb_check_dotnet_rollup/done", value:TRUE);

if (len(latest) == 0 || report == "")
  exit(0, "No Microsoft .NET rollups were found.");

foreach ver (keys(latest))
{
  if(empty_or_null(latest[ver]['eff']))
  {
    set_kb_item(name:kb_base+ver+"/latest", value:"none");
    report += '\n\n .NET Version                  : ' + ver;
    report += '\n   No cumulative updates are installed.\n';
  }
  else
  {
    report += '\n\n .NET version                  : ' + ver +
              '\n Latest effective update level : ' + latest[ver]['eff'] +
              '\n File checked                  : ' + latest[ver]['file_name'] +
              '\n File version                  : ' + latest[ver]['file_ver'] +
              '\n Associated KB                 : ' + latest[ver]['kb_str'] + '\n';
    set_kb_item(name:kb_base+ver+"/latest", value:latest[ver]['eff']);
  }
}
port = kb_smb_transport();
if(!port)port = 445;

security_note(port:port, extra:report);
