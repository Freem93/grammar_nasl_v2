#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71315);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-5059");
  script_bugtraq_id(64081);
  script_osvdb_id(100767);
  script_xref(name:"MSFT", value:"MS13-100");
  script_xref(name:"IAVB", value:"2013-B-0136");

  script_name(english:"MS13-100: Vulnerabilities in Microsoft SharePoint Server Could Allow Remote Code Execution (2904244)");
  script_summary(english:"Checks SharePoint / Office Web Apps version");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of Office SharePoint Server, or Office Web Apps installed
on the remote host are affected by code execution vulnerabilities. By
sending specially crafted page content to a SharePoint server, a
remote, authenticated attacker could execute arbitrary code on the
remote host subject to the privileges of the W3WP service account.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-100");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2010,
SharePoint Server 2013 and Office Web Apps 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/12/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

bulletin = "MS13-100";
kbs = make_list(
  2850058,
  2553298,
  2837629,
  2837631,
  2910228
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

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

# Get path information for Office Web Apps.
owa_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall\Office15.WacServer\InstallLocation"
);

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

######################################################################
# SharePoint Server 2010 SP1 / SP2
#
# [KB2553298] - ascalc.dll: 14.0.7011.1000
######################################################################
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2553298",
    path : sps_2010_path + "Bin\ascalc.dll",
    fix  : "14.0.7011.1000"
  );
}

######################################################################
# SharePoint Server 2013
#
# [KB2850058] MSSCPI.dll: 15.0.4551.1001
# [KB2837631] xlsrv.dll: 15.0.4551.1006
# [KB2837629] ascalc.dll: 15.0.4545.1000
######################################################################
if (sps_2013_path)
{
  name = "Office SharePoint Server 2013";

  check_vuln(
    name : name,
    kb   : "2850058",
    path : sps_2013_path + "Bin\MSSCPI.dll",
    fix  : "15.0.4551.1001"
  );

  check_vuln(
    name : name,
    kb   : "2837631",
    path : sps_2013_path + "Bin\xlsrv.dll",
    fix  : "15.0.4551.1006"
  );

  check_vuln(
    name : name,
    kb   : "2837629",
    path : sps_2013_path + "Bin\ascalc.dll",
    fix  : "15.0.4545.1000"
  );
}

######################################################################
# Office Web Apps 2013
######################################################################
if (owa_2013_path)
{
  check_vuln(
    name : "Office Web Apps 2013",
    kb   : "2910228",
    path : windir + "\Microsoft.NET\assembly\GAC_MSIL\Microsoft.Office.Web.Apps.Environment.WacServer\v4.0_15.0.0.0__71e9bce111e9429c\Microsoft.Office.Web.Apps.Environment.WacServer.dll",
    fix  : "15.0.4511.1006"
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
