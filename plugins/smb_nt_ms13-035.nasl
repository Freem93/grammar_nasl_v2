#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65882);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-1289");
  script_bugtraq_id(58883);
  script_osvdb_id(92129);
  script_xref(name:"MSFT", value:"MS13-035");
  script_xref(name:"IAVA", value:"2013-A-0083");

  script_name(english:"MS13-035: Vulnerability in HTML Sanitization Component Could Allow Elevation of Privilege (2821818)");
  script_summary(english:"Local patch check");

  script_set_attribute(attribute:"synopsis", value:"The remote host is affected by a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of InfoPath, SharePoint Server, SharePoint Foundation,
Groove Server, or Office Web Apps running on the remote host is
affected by an unspecified cross-site scripting vulnerability. An
attacker could exploit this by tricking a user into requesting
specially crafted SharePoint content, resulting in arbitrary script
code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-035");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for InfoPath 2010, SharePoint
Server 2010, SharePoint Foundation 2010, Groove Server 2010, and
Office Web Apps 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove_server");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:infopath");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_web_apps");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_foundation");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "office_installed.nasl", "groove_server_installed.nasl", "ms_bulletin_checks_possible.nasl");
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
  path = ereg_replace(string:path, pattern:"^[A-Za-z]:(.*)", replace:"\1\");

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

bulletin = "MS13-035";
kbs = make_list(
  '2687421',
  '2687422',
  '2687424',
  '2760406',
  '2760408',
  '2760777',
  '2810059'
);
if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Connect to the registry.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get path information for SharePoint Server 2010.
sps_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\14.0\InstallPath"
);

# Get path information for SharePoint Services 3.0 or SharePoint Foundation 2010.
spf_2010_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Shared Tools\Web Server Extensions\14.0\Location"
);

# Get path information for Groove Server 2010.
gs_paths = get_kb_list('SMB/groove_server/path');

# Get path and SP information for InfoPath 2010
ip2010_paths = get_kb_list("SMB/Office/InfoPath/14.*/ProductPath");
if (!isnull(ip2010_paths))
{
  # there should be at most one InfoPath 2010 install per host
  ip2010_paths = make_list(ip2010_paths);
  ip_path = ip2010_paths[0];
  office_sp2010 = get_kb_item("SMB/Office/2010/SP");
}

# Close connection to registry.
RegCloseKey(handle:hklm);
close_registry(close:FALSE);

# Get path information for Common Files.
commonprogramfiles = hotfix_get_commonfilesdir();
if (!commonprogramfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

# Get path information for Office Web Apps.
owa_2010_path = sps_2010_path;

# InfoPath 2010 SP0 / SP1
if (!isnull(ip_path) && office_sp2010 == 1)
{
  ip_path = ereg_replace(string:ip_path, pattern:"(.*)(\\[^\\]+)$", replace:"\1");
  name = "InfoPath 2010";

  check_vuln(
    name : name,
    kb   : "2687422",
    path : ip_path + "\Infopath.Exe",
    fix  : "14.0.6134.5004"
  );

  check_vuln(
    name : name,
    kb   : "2760406",
    path : ip_path + "\Ipeditor.dll",
    fix  : "14.0.6134.5004"
  );
}

# SharePoint Server 2010 SP1
if (sps_2010_path)
{
  name = "Office SharePoint Server 2010";

  check_vuln(
    name : name,
    kb   : "2760408",
    path : sps_2010_path + "Service\Microsoft.resourcemanagement.dll",
    fix  : "4.0.2450.49"
  );

  check_vuln(
    name : name,
    kb   : "2687421",
    path : commonprogramfiles + "\Microsoft Shared\Web Server Extensions\14\BIN\Osafehtm.dll",
    fix  : "14.0.6134.5004"
  );
}

# Groove Server 2010 SP1
foreach path (gs_paths)
{
  if (path[strlen(path) - 1] != "\") path += "\";
  path += "Groovems.dll";
  ver = get_ver(path);

  if (ver =~ "^14\.")
  {
    check_vuln(
      name : "Groove Server 2010",
      kb   : "2687424",
      path : path,
      fix  : "14.0.6134.5004",
      ver  : ver
    );
  }
}

# SharePoint Foundation 2010 SP1
if (spf_2010_path)
{
  path = spf_2010_path + "Bin\Onetutil.dll";
  ver = get_ver(path);

  if (ver && ver =~ "^14\.")
  {
    check_vuln(
      name : "SharePoint Foundation 2010",
      kb   : "2810059",
      path : path,
      ver  : ver,
      fix  : "14.0.6137.5002"
    );
  }
}

# Office Web Apps 2010 SP1
if (owa_2010_path)
{
  check_vuln(
    name : "Office Web Apps 2010",
    kb   : "2760777",
    path : owa_2010_path + "WebServices\ConversionService\Bin\Converter\sword.dll",
    fix  : "14.0.6134.5000"
  );
}

hotfix_check_fversion_end();

if (!vuln)
  audit(AUDIT_HOST_NOT, 'affected');
# Flag the system as vulnerable.
set_kb_item(name:"SMB/Missing/" + bulletin, value:TRUE);
set_kb_item(name:"www/0/XSS", value:TRUE);
hotfix_security_warning();
