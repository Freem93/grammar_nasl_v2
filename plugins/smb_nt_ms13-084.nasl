#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70336);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-3889", "CVE-2013-3895");
  script_bugtraq_id(62800, 62829);
  script_osvdb_id(98218, 98219);
  script_xref(name:"MSFT", value:"MS13-084");
  script_xref(name:"IAVB", value:"2013-B-0116");

  script_name(english:"MS13-084: Vulnerabilities in Microsoft SharePoint Server Could Allow Remote Code Execution (2885089)");
  script_summary(english:"Checks SharePoint / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of Office SharePoint Server, SharePoint Server, Windows
SharePoint Services, SharePoint Foundation, or Office Web Apps
installed on the remote host are affected by multiple vulnerabilities :

  - A remote code execution vulnerability exists in the way
    that Microsoft Office Services and Web Apps parse
    content in specially crafted files. (CVE-2013-3889)

  - An elevation of privilege vulnerability exists.
    (CVE-2013-3895)");

  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-084");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007,
SharePoint Server 2010, SharePoint Foundation 2010, SharePoint Server
2013, and Office Web Apps 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

function get_ver()
{
  local_var fh, path, rc, share, ver;

  path = _FCT_ANON_ARGS[0];

  share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:path);

  rc = NetUseAdd(share:share);
  if (rc != 1)
  {
    NetUseDel();
    audit(AUDIT_SHARE_FAIL, share);
  }

  ver = NULL;
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:'\\1\\');

  fh = CreateFile(
    file               : path,
    desired_access     : GENERIC_READ,
    file_attributes    : FILE_ATTRIBUTE_NORMAL,
    share_mode         : FILE_SHARE_READ,
    create_disposition : OPEN_EXISTING
  );
  if (!isnull(fh))
  {
    ver = GetFileVersion(handle:fh);
    ver = join(ver, sep:".");
    CloseFile(handle:fh);
  }

  NetUseDel(close:FALSE);

  return ver;
}

function check_vuln(fix, kb, name, path, ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS13-084";
kbs = make_list(
  2589365, 2596741, 2752002, 2760561,
  2826022, 2826028, 2826029, 2826030,
  2826036, 2827222, 2827327);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for SharePoint Server 2007
sps_2007_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\12.0\InstallPath"
);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Get the path information for SharePoint Server 2013
sps_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\15.0\InstallPath"
);

# Get the path information for SharePoint Service 3.0
sps_30_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0\Location"
);

# Get path information for SharePoint Foundation 2010.
spf_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\Location"
);

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir))
  exit(1, "Failed to determine the location of %windir%.");

# Get path information for Common Files.
commonprogramfiles = hotfix_get_commonfilesdir();
if (isnull(commonprogramfiles))
  exit(1, "Failed to determine the location of %commonprogramfiles%.");

# Get path information for Office Web Apps.
owa_2010_path = sps_2010_path;

######################################################################
# SharePoint Server 2007 SP3
#
# [KB2827327] xlsrv.dll: 12.0.6683.5002
######################################################################
if (sps_2007_path)
{
  name = "Office SharePoint Server 2007";

  get_kb_item_or_exit("SMB/Registry/Uninstall/Enumerated", exit_code:1);

  check_vuln(
    name : name,
    kb   : "2827327",
    path : sps_2007_path + "Bin\xlsrv.dll",
    fix  : "12.0.6683.5002"
  );

  display_names = get_kb_list("SMB/Registry/HKLM/SOFTWARE/Microsoft/Windows/CurrentVersion/Uninstall/*/DisplayName");
  if (display_names)
  {
    kb2596741 = FALSE;
    foreach item (keys(display_names))
    {
      if ('Security Update for Microsoft Office SharePoint Server 2007 (KB2596741)' >< display_names[item])
      {
        kb2596741 = TRUE;
        break;
      }
    }
  }
  if (!kb2596741)
  {
    hotfix_add_report('\n  According to the registry, KB2596741 is missing.\n', bulletin:bulletin, kb:2596741);
    vuln++;
  }
}

######################################################################
# SharePoint Foundation 2010 SP1 / SP2
#
# [KB2589365] Onetutil.dll: 14.0.7106.5002
######################################################################
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^14\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2589365",
      path : path,
      ver  : ver,
      fix  : "14.0.7106.5002"
    );
  }
}

######################################################################
# SharePoint Server 2010 SP1 / SP2
#
# [KB2826029]- xlsrv.dll: 14.0.7108.5000
# [KB2826022] - sword.dll: 14.0.7109.5000
######################################################################
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2826029",
    path : sps_2010_path + "Bin\xlsrv.dll",
    fix  : "14.0.7108.5000"
  );

  check_vuln(
    name : "Office SharePoint Server 2010",
    kb   : "2826022",
    path : sps_2010_path + "WebServices\WordServer\Core\sword.dll",
    fix  : "14.0.7109.5000"
  );
}

######################################################################
# SharePoint Server 2013
#
# [KB2827222] Microsoft.Office.Excel.Server.dll: 15.0.4525.1000
# [KB2760561] Microsoft.Office.Server.PowePoint.dll: 15.0.4525.1000
# [KB2752002] xlsrv.dll: 15.0.4535.1007
# [KB2826036] sword.dll: 15.0.4535.1507
######################################################################
if (sps_2013_path)
{
  name = "Office SharePoint Server 2013";

  check_vuln(
    name : name,
    kb   : "2827222",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Excel.Server\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Excel.Server.dll",
    fix  : "15.0.4525.1000"
  );

  check_vuln(
    name : name,
    kb   : "2760561",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Server.PowerPoint\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Server.PowerPoint.dll",
    fix  : "15.0.4521.1000"
  );

  check_vuln(
    name : name,
    kb   : "2752002",
    path : sps_2013_path + "Bin\xlsrv.dll",
    fix  : "15.0.4535.1507"
  );

  check_vuln(
    name : name,
    kb   : "2826036",
    path : sps_2013_path + "WebServices\ConversionServices\sword.dll",
    fix  : "15.0.4535.1507"
  );
}

######################################################################
# Office Web Apps 2010 SP1 / SP2
#
# [KB2826028] xlsrv.dll: 14.0.7108.5000
# [KB2826030] sword.dll: 14.0.7106.5001
######################################################################
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2826028",
    path : owa_2010_path + "Bin\xlsrv.dll",
    fix  : "14.0.7108.5000"
  );

  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2826030",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.7109.5000"
  );
}


if (vuln)
{
  set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
