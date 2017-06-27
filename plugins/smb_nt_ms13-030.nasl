#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(65877);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/06 14:12:41 $");

  script_cve_id("CVE-2013-1290");
  script_bugtraq_id(58844);
  script_osvdb_id(92123);
  script_xref(name:"MSFT", value:"MS13-030");

  script_name(english:"MS13-030: Vulnerability in SharePoint Could Allow Information Disclosure (2827663)");
  script_summary(english:"Checks file versions");

  script_set_attribute(attribute:"synopsis", value:
"The version of SharePoint running on the remote host has an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft SharePoint Server 2013 on the remote host is
affected by an information disclosure vulnerability due to a flaw in
the way SharePoint server enforces access controls on specific
SharePoint Lists.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-030");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for SharePoint Server 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/04/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/04/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint");
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

function check_vuln(fix, kb, name, path, ver, min_ver, pre_req)
{
  local_var info;

  if (isnull(ver))
    ver = get_ver(path);

  if (isnull(ver) || ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
    return 0;

  # If min_ver is supplied, make sure the version is higher than the min_ver
  if (min_ver && ver_compare(ver:ver, fix:min_ver, strict:FALSE) == -1)
    return 0;

  if(!isnull(pre_req))
    fix = fix + ' (prerequisite: ' + pre_req + ')';

  info =
    '\n  Product           : ' + name +
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix + '\n';
  hotfix_add_report(info, bulletin:bulletin, kb:kb);

  vuln = TRUE;
}

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");
bulletin = 'MS13-030';
kb = '2737969';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_NOTE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

root = hotfix_get_systemroot();
if (isnull(root)) audit(AUDIT_FN_FAIL, 'hotfix_get_systemroot');

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Get the path information for SharePoint Server 2013
sps_2013_path = get_registry_value(
  handle : hklm,
  item   : "SOFTWARE\Microsoft\Office Server\15.0\InstallPath"
);

RegCloseKey(handle:hklm);

if (isnull(sps_2013_path))
{
  close_registry();
  audit(AUDIT_NOT_INST, 'SharePoint Server 2013');
}
else
{
  close_registry(close:FALSE);
}

# SharePoint Server 2013
if (sps_2013_path)
{
  check_vuln(
    name    : "SharePoint Server 2013",
    kb      : kb,
    path    : sps_2013_path + "Bin\Microsoft.SharePoint.Publishing.dll",
    fix     : "15.0.4481.1507",
    pre_req : "KB2768001"
  );
}

hotfix_check_fversion_end();

if (!vuln) audit(AUDIT_HOST_NOT, 'affected');

# Flag the system as vulnerable
set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
hotfix_security_note();
