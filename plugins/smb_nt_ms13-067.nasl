#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69827);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id(
    "CVE-2013-0081",
    "CVE-2013-1315",
    "CVE-2013-1330",
    "CVE-2013-3179",
    "CVE-2013-3180",
    "CVE-2013-3847",
    "CVE-2013-3848",
    "CVE-2013-3849",
    "CVE-2013-3857",
    "CVE-2013-3858"
  );
  script_bugtraq_id(
    62165,
    62167,
    62168,
    62169,
    62205,
    62221,
    62224,
    62226,
    62227,
    62254
  );
  script_osvdb_id(
    97116,
    97117,
    97118,
    97119,
    97120,
    97121,
    97122,
    97129,
    97130,
    97131
  );
  script_xref(name:"EDB-ID", value:"28238");
  script_xref(name:"IAVA", value:"2013-A-0174");
  script_xref(name:"MSFT", value:"MS13-067");

  script_name(english:"MS13-067: Vulnerabilities in Microsoft SharePoint Server Could Allow Remote Code Execution (2834052)");
  script_summary(english:"Checks SharePoint / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of Office SharePoint Server, SharePoint Server, Windows
SharePoint Services, SharePoint Foundation, or Office Web Apps
installed on the remote host are affected by multiple vulnerabilities :

  - A denial of service vulnerability exits that could cause
    the W3WP process to stop responding. (CVE-2013-0081)

  - A remote code execution vulnerability exists in the way
    Microsoft Office Services and Web Apps parse content in
    specially crafted files. (CVE-2013-1315)

  - A remote code execution vulnerability exists in the way
    SharePoint Server handles unassigned workflows.
    (CVE-2013-1330)

  - An unspecified cross-site scripting vulnerability
    exists. (CVE-2013-3179)

  - An unspecified POST cross-site scripting vulnerability
    exists. (CVE-2013-3180)

  - Multiple memory corruption vulnerabilities exist in the
    way that Microsoft Office software parses specially
    crafted files. (CVE-2013-2847, CVE-2013-3848,
    CVE-2013-3849, CVE-2013-3857, CVE-2013-3858)");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/528546/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS13-067");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2007,
SharePoint Server 2010, SharePoint Foundation 2010, SharePoint Server
2013, SharePoint Foundation 2013, and Office Web Apps 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl", "microsoft_sharepoint_installed.nbin");
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

bulletin = "MS13-067";
kbs = make_list(
  2810083, 2817305, 2817315, 2817393,
  2817372, 2810067, 2760420, 2810061,
  2760595, 2760589, 2553408,
  2760755, 2760594, 2817384
);
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

# Get path information for SharePoint Services 2.0
sps_20_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\6.0\Location"
);

# Get the path information for SharePoint Service 3.0
sps_30_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\12.0\Location"
);

# Check if KB2553408 is installed
kb2553408 = FALSE;
res = get_reg_name_value_table(handle:hklm, key:"SOFTWARE\Classes\Installer\Products\00004109880100000100000000F01FEC\Patches");
foreach item (res)
{
  if ('9010880000100014.0.7015.1000;:#9010880000100014.0.7015.1000' >< item ||
      '9010880000100014.0.6029.1000;:#9010880000100014.0.6029.1000' >< item)
    kb2553408 = TRUE;
}

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
if (isnull(windir)) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

# Get path information for Common Files.
commonprogramfiles = hotfix_get_commonfilesdir();
if (!commonprogramfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

# Get path information for Office Web Apps.
owa_2010_path = sps_2010_path;

######################################################################
# SharePoint Services 2.0
#
# [KB2810061] onetutil.dll - 11.0.8402.0
######################################################################
if (sps_20_path)
{
  name = "Office SharePoint Services 2.0";

  check_vuln(
    name : "SharePoint Services 2.0",
    kb   : "2810061",
    path : sps_20_path + "\ISAPI\OWSSVR.DLL",
    fix  : "11.0.8402.0"
  );
}

######################################################################
# SharePoint Server 2007 SP3
#
# [KB2760589]  xlsrv.dll - 12.0.6676.5000
# [KB2760420] owssvr.dll - 12.0.6676.5000
######################################################################
if (sps_2007_path)
{
  name = "Office SharePoint Server 2007";

  check_vuln(
    name : name,
    kb   : "2760589",
    path : sps_2007_path + "Bin\xlsrv.dll",
    fix  : "12.0.6676.5000"
  );

  if (sps_30_path)
  {
    check_vuln(
      name : name,
      kb   : "2760420",
      path : sps_30_path + "\ISAPI\OWSSVR.DLL",
      fix  : "12.0.6676.5000"
    );
  }
}

######################################################################
# SharePoint Foundation 2010 SP1 / SP2
#
# [KB2810067] Onetutil.dll: 14.0.7105.5000
######################################################################
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^14\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2810067",
      path : path,
      ver  : ver,
      fix  : "14.0.7105.5000"
    );
  }
}

######################################################################
# SharePoint Server 2010 SP1 / SP2
#
# [KB2817393] - MSSCPI.dll: 14.0.7105.5000
# [KB2817372] - SVRSETUP.dll: 14.0.7106.5000
# [KB2760595] - xlsrv.dll: 14.0.7104.5000
# [KB2760755] - wdsrvworker.dll: 14.0.6112.5000
######################################################################
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2817393",
    path : sps_2010_path + "Bin\MSSCPI.dll",
    fix  : "14.0.7105.5000"
  );

  check_vuln(
    name : name,
    kb   : "2817372",
    path : commonprogramfiles + "\Microsoft Shared\SERVER14\Server Setup Controller\SVRSETUP.DLL",
    fix  : "14.0.7106.5000"
  );

  check_vuln(
    name : name,
    kb   : "2760595",
    path : sps_2010_path + "Bin\xlsrv.dll",
    fix  : "14.0.7104.5000"
  );

  check_vuln(
    name : name,
    kb   : "2760755",
    path : sps_2010_path + "WebServices\WordServer\Core\wdsrvworker.dll",
    fix  : "14.0.6112.5000"
  );

  sps2010edition = get_kb_item("SMB/Microsoft SharePoint/14.0/Edition");
  if (!kb2553408 && (!empty_or_null(sps2010edition) && 'Foundation' >!< sps2010edition))
  {
    hotfix_add_report('  According to the registry, KB2553408 is missing.\n', bulletin:bulletin, kb:'2553408');
    vuln++;
  }
}

######################################################################
# SharePoint Foundation 2013
#
# [KB2817315] Onetutil.dll: 15.0.4535.1000
######################################################################
if (spf_2013_path)
{
  path = spf_2013_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^15\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2013",
      kb   : "2817315",
      path : path,
      ver  : ver,
      fix  : "15.0.4535.1000"
    );
  }
}

######################################################################
# SharePoint Server 2013
#
# [KB2810083] - MSSCPI.dll: 14.0.7105.5000
# [KB2817305] - sword.dlla: 15.0.4535.1000
######################################################################
if (sps_2013_path)
{
  name = "Office SharePoint Server 2013";

  check_vuln(
    name : name,
    kb   : "2810083",
    path : sps_2013_path + "Bin\MSSCPI.dll",
    fix  : "15.0.4535.1000"
  );

  check_vuln(
    name : name,
    kb   : "2817305",
    path : sps_2013_path + "\WebServices\ConversionServices\sword.dll",
    fix  : "15.0.4525.1000"
  );
}

######################################################################
# Office Web Apps 2010 SP1 / SP2
#
# [KB2760594] xlsrv.dll: 14.0.7104.5000
# [KB2817384] sword.dll: 14.0.7106.5001
######################################################################
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2760594",
    path : owa_2010_path + "Bin\xlsrv.dll",
    fix  : "14.0.7104.5000"
  );

  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2817384",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.7106.5001"
  );
}


if (vuln)
{
  set_kb_item(name:"www/0/XSS", value:TRUE);

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
