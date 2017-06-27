#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65213);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/06 14:12:41 $");

  script_cve_id(
    "CVE-2013-0080",
    "CVE-2013-0083",
    "CVE-2013-0084",
    "CVE-2013-0085"
  );
  script_bugtraq_id(58367, 58370, 58371, 58372);
  script_osvdb_id(91149, 91150, 91151, 91152);
  script_xref(name:"MSFT", value:"MS13-024");

  script_name(english:"MS13-024: Vulnerabilities in SharePoint Could Allow Elevation of Privilege (2780176)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The version of SharePoint running on the remote host has multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The versions of Microsoft SharePoint Server 2010 and SharePoint
Foundation 2010 have the following vulnerabilities :

  - A callback function vulnerability exists that could
    allow an attacker to read data or perform other
    unauthorized actions. (CVE-2013-0080)

  - A cross-site scripting vulnerability exists.
    (CVE-2013-0083)

  - A directory traversal vulnerability exists that could
    allow an attacker to read arbitrary files.
    (CVE-2013-0084)

  - A buffer overflow exists that could result in a denial
    of service. Code execution is reportedly not possible.
    (CVE-2013-0085)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-024");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for SharePoint Server 2010 and
SharePoint Foundations 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

  share = hotfix_path2share(path:path);

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

function check_vuln(fix, kb, name, path, ver, min_ver)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  # If min_ver is supplied, make sure the version is higher than the min_ver
  if (min_ver && ver_compare(ver:ver, fix:min_ver, strict:FALSE) == -1)
    return 0;

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");
bulletin = 'MS13-024';
kbs = make_list('2553407', '2687418');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# needed for SharePoint Server 2010 check
root = hotfix_get_systemroot();
if (isnull(root)) audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for SharePoint Server 2010
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Get the path information for SharePoint Foundation 2010
spf_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\Location"
);

RegCloseKey(handle:hklm);

if (isnull(sps_2010_path) && isnull(spf_2010_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'SharePoint Server/Foundation 2010');
}
else
{
  close_registry(close:FALSE);
}

# SharePoint Server 2010 SP1
if (sps_2010_path)
{
  check_vuln(
    name : "SharePoint Server 2010",
    kb   : "2589280",
    path : root + "\assembly\GAC_MSIL\Microsoft.Office.Server.WebAnalytics.UI\14.0.0.0__71e9bce111e9429c\Microsoft.office.server.webanalytics.ui.dll",
    fix  : "14.0.6129.5000"
  );
}

# SharePoint Foundation 2010 SP1
#
# this check will also (correctly) identify vulnerable SharePoint Server 2010 systems.
# footnote 1 in the bulletin says:
#   For supported editions of Microsoft SharePoint Server 2010, in
#   addition to the security update package for Microsoft SharePoint 2010
#   (2553407), customers also need to install the security update for
#   Microsoft SharePoint Foundation 2010 (2687418) to be protected from
#   the vulnerabilities described in this bulletin.
if (spf_2010_path)
{
  check_vuln(
    name : "SharePoint Foundation 2010",
    kb   : "2687418",
    path : spf_2010_path + "Bin\Onetutil.dll",
    min_ver: "14.0.6029.1000", # SP 1
    fix  : "14.0.6134.5001"
  );
}

hotfix_check_fversion_end();

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
set_kb_item(name:"www/0/XSS", value:TRUE);
hotfix_security_warning();
