#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93962);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/05/24 14:05:10 $");

  script_name(english:"Microsoft Security Rollup Enumeration");
  script_summary(english:"Enumerates installed Microsoft security rollups.");

  script_set_attribute(attribute:"synopsis", value:
"This plugin enumerates installed Microsoft security rollups.");
  script_set_attribute(attribute:"description", value:
"Nessus was able to enumerate the Microsoft security rollups installed
on the remote Windows host.");
  # https://blogs.technet.microsoft.com/windowsitpro/2016/08/15/further-simplifying-servicing-model-for-windows-7-and-windows-8-1/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b23205aa");
  script_set_attribute(attribute:"solution", value:"n/a");

  script_set_attribute(attribute:"risk_factor",value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/11");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl","wmi_enum_qfes.nbin");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);
  script_timeout(30*60);

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

# in order from latest to earliest
rollup_dates = make_list(
  "05_2017",
  "04_2017",
  "03_2017",
  "01_2017",
  "12_2016",
  "11_2016",
  "10_2016"
);
rollup_patches = {
  # rollup    #   arguments to pass to hotfix_check_fversion, "dir" argument also passed                      # kb list
  # date      #   if present

  # October 2016
  # 7 / 2008 R2
  "10_2016" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "ntoskrnl.exe", "version": "6.1.7601.23564"}, {"cum": 3185330, "sec": 3192391, "pre": 3192403}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "Gdiplus.dll", "version": "6.2.9200.21976"}, {"cum": 3185332, "sec": 3192393, "pre": 3192406}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "Gdiplus.dll", "version": "6.3.9600.18468"}, {"cum": 3185331, "sec": 3192392, "pre": 3192404}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "Gdiplus.dll", "version": "10.0.10240.17146"}, {"cum": 3192440}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "Gdiplus.dll", "version": "10.0.10586.633"}, {"cum": 3192441}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "Gdiplus.dll", "version": "10.0.14393.321"}, {"cum": 3194798}]],

  # November 2016
  # 7 / 2008 R2
  "11_2016" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "ntoskrnl.exe", "version": "6.1.7601.23569"}, {"cum": 3197868, "sec": 3197867, "pre": 3197869}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "ntoskrnl.exe", "version": "6.2.9200.22005"}, {"cum": 3197877, "sec": 3197876, "pre": 3197878}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18524"}, {"cum": 3197874, "sec": 3197873, "pre": 3197875}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10240.17184"}, {"cum": 3198585}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10586.672"}, {"cum": 3198586}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.447"}, {"cum": 3200970}]],

  # December 2016
  # 7 / 2008 R2
  "12_2016" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23601"}, {"cum": 3207752, "sec": 3205394}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "bcrypt.dll", "version": "6.2.9200.22037"}, {"cum": 3205409, "sec": 3205408}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18533"}, {"cum": 3205401, "sec": 3205400}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.10240.17202"}, {"cum": 3205383}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "user32.dll", "version": "10.0.10586.713"}, {"cum": 3205386}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.576"}, {"cum": 3206632}]],

  # January 2017
  # 7 / 2008 R2
  "01_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23642"}, {"cum": 3212646, "sec": 3212642}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17236"}, {"cum": 3210720}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.753"}, {"cum": 3210721}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.693"}, {"cum": 3213986}]],

  # February 2017 - Canceled :)

  # March 2017
  # 7 / 2008 R2
  "03_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23677"}, {"cum": 4012215, "sec": 4012212}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.2.9200.22097"}, {"cum": 4012217, "sec": 4012214}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18603"}, {"cum": 4012216, "sec": 4012213}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17319"}, {"cum": 4012606}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.839"}, {"cum": 4013198}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.953"}, {"cum": 4013429}]],

  # April 2017
  # 7 / 2008 R2#
  "04_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23714"}, {"cum": 4015549, "sec": 4015546}],
  # 2012#
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.2.9200.22109"}, {"cum": 4015551, "sec": 4015548}],
  # 8.1 / 2012 R2#
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18623"}, {"cum": 4015550, "sec": 4015547}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17354"}, {"cum": 4015221}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.873"}, {"cum": 4015219}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.1066"}, {"cum": 4015217}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.138"}, {"cum": 4015583}]],

  # May 2017
  # 7 / 2008 R2
  "05_2017" : [[{"os":'6.1', "sp":1, "path":"\System32", "file": "bcrypt.dll", "version": "6.1.7601.23796"}, {"cum": 4019264, "sec": 4019263}],
  # 2012
               [{"os":'6.2', "sp":0, "path":"\System32", "file": "gdi32.dll", "version": "6.2.9200.22139"}, {"cum": 4019214, "sec": 4019216}],
  # 8.1 / 2012 R2
               [{"os":'6.3', "sp":0, "path":"\System32", "file": "win32k.sys", "version": "6.3.9600.18683"}, {"cum": 4019215, "sec": 4019213}],
  # 10
               [{"os":'10', "sp":0, "os_build":"10240", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10240.17394"}, {"cum": 4019474}],
  # 10 1511 (AKA 10586)
               [{"os":'10', "sp":0, "os_build":"10586", "path":"\System32", "file": "gdi32.dll", "version": "10.0.10586.916"}, {"cum": 4019473}],
  # 10 1607 (AKA 14393)
               [{"os":'10', "sp":0, "os_build":"14393", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.14393.1198"}, {"cum": 4019472}],
  # 10 1703 (AKA 15063)
               [{"os":'10', "sp":0, "os_build":"15063", "path":"\System32", "file": "ntoskrnl.exe", "version": "10.0.15063.296"}, {"cum": 4016871}]]

};

global_var registry_kbs;

function is_patched(os, sp, arch, os_build, file, version, dir, path, min_version, bulletin, kb, product, channel, channel_product, channel_version, rollup)
{
  local_var r, ver_report, report_text;
  local_var my_sp, my_os, my_arch, my_os_build, systemroot;

  my_os = get_kb_item("SMB/WindowsVersion");
  my_sp = get_kb_item("SMB/CSDVersion");
  my_arch = get_kb_item("SMB/ARCH");
  my_os_build = get_kb_item("SMB/WindowsVersionBuild");
  if ( my_sp )
  {
    my_sp = ereg_replace(pattern:".*Service Pack ([0-9]).*", string:my_sp, replace:"\1");
    my_sp = int(my_sp);
  }
  else my_sp = 0;

  if ( os >!< my_os ) return 0;
  if ( ! isnull(sp) && my_sp != sp ) return 0;
  if ( ! isnull(arch) && my_arch != arch ) return 0;
  if ( ! isnull(os_build) && my_os_build != os_build ) return 0;

  systemroot = hotfix_get_systemroot();
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
        set_kb_item(name:"smb_rollup/version_report/"+rollup,value:report_text);
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
    item = eregmatch(pattern:"[^A-Za-z](KB\d{5,})([^\d]|$)", string:package);
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

foreach rollup_date (rollup_dates)
{
  patch_checks = rollup_patches[rollup_date];
  foreach patch_check (patch_checks)
  {
    file_check = patch_check[0];
    if(is_patched(os:file_check["os"],
                  sp:file_check["sp"],
                  os_build:file_check["os_build"],
                  file:file_check["file"],
                  version:file_check["version"],
                  dir:file_check["dir"],
                  path:file_check["path"],
                  rollup:rollup_date))
    {
      kb_list = patch_check[1];

      kb_str =  kb_list["cum"];
      if(kb_list['sec']) kb_str += ", " + kb_list['sec'];
      if(kb_list['pre']) kb_str += ", " + kb_list['pre'];
      
      if(latest_eff == "") latest_eff = rollup_date;

      cur_date = split(rollup_date, sep:"_", keep:FALSE);
      cur_date = cur_date[1] + "." + cur_date[0];
      last_date = split(latest_eff, sep:"_", keep:FALSE);
      last_date = last_date[1] + "." + last_date[0];

      if(ver_compare(ver:cur_date, fix:last_date) >=0 )
      {
        latest_eff = rollup_date;
        latest_file = systemroot + file_check["path"] + "\" + file_check["file"];
        latest_ver = file_check["version"];
      }

      set_kb_item(name:"smb_rollup/"+rollup_date, value:1);
      set_kb_item(name:"smb_rollup/"+rollup_date+"/file", value:latest_file);
      set_kb_item(name:"smb_rollup/"+rollup_date+"/file_ver", value:latest_ver);

      if(kb_installed(kb_list["cum"]))
      {
        report += '\n Cumulative Rollup : ' + rollup_date + ' [KB' + kb_list["cum"] + ']';
        set_kb_item(name:"smb_rollup/" + rollup_date + "/cum", value:kb_list["cum"]);
      }
      if(kb_installed(kb_list["sec"]))
      {
        report += '\n Security Rollup : ' + rollup_date + ' [KB' + kb_list["sec"] + ']';
        set_kb_item(name:"smb_rollup/" + rollup_date + "/sec", value:kb_list["sec"]);
      }
      if(kb_installed(kb_list["pre"]))
      {
        report += '\n Preview of Monthly Rollup : ' + rollup_date + ' [KB' + kb_list["pre"] + ']';
        set_kb_item(name:"smb_rollup/" + rollup_date + "/preview", value:kb_list["pre"]);
      }
    }
  }
}

# cleanup connection
NetUseDel();

set_kb_item(name:"smb_check_rollup/done", value:TRUE);

if(latest_eff == "" && report == "")
  exit(0, "No Microsoft rollups were found.");

if(latest_eff == "")
{
  set_kb_item(name:"smb_rollup/latest", value:"none");
  report += '\n   No cumulative updates are installed.\n';
}
else
{ 
  report += '\n\n Latest effective update level : ' + latest_eff +
            '\n File checked                  : ' + latest_file +
            '\n File version                  : ' + latest_ver +
            '\n Associated KB                 : ' + kb_str + '\n';
  set_kb_item(name:"smb_rollup/latest", value:latest_eff);
}

port = kb_smb_transport();
if(!port)port = 445;

security_note(port:port, extra:report);
