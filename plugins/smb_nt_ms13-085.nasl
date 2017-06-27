#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70337);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2013-3889", "CVE-2013-3890");
  script_bugtraq_id(62824, 62829);
  script_osvdb_id(98219, 98220);
  script_xref(name:"MSFT", value:"MS13-085");

  script_name(english:"MS13-085: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (2885080)");
  script_summary(english:"Checks file versions.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office component installed on the remote host is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is running a version of Microsoft Office,
Microsoft Excel, Office Compatibility Pack, or Microsoft Excel Viewer
that is affected by remote code execution vulnerabilities in the way
that Microsoft Excel parses file contents. (CVE-2013-3889,
CVE-2013-3890).

If an attacker can trick a user on the affected host into opening a
specially crafted file, it may be possible to leverage these issues to
read arbitrary files on the target system or execute arbitrary code,
subject to the user's privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-085");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2007, Excel 2010,
Excel 2013, Office 2007, Office 2010, Office 2013, Excel Viewer, and
Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = "MS13-085";
kbs = make_list(
  2760585, 2760591, 2817623, 2826023, 2826033, 2826035, 2827238, 2827324, 2827326, 2827328, 2885080
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

info = "";
vuln = FALSE;

######################################################################
# Office
######################################################################
installs = get_kb_list("SMB/Office/Excel/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/Excel/' - '/ProductPath';
    ver = split(version, sep:'.', keep:FALSE);
    for (i=0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);
    path = installs[install];
    path = path - '\\Excel.exe';
    info = '';

    # Office 2007 SP3
    if (ver[0] == 12)
    # Ensure share is accessible
    {
      office_sp = get_kb_item("SMB/Office/2007/SP");
      if (!isnull(office_sp) && office_sp == 3)
      {
        if (
          (ver[0] == 12 && ver[1] == 0 && ver[2] >= 6611) &&
          (
            (ver[0] == 12 && ver[1] == 0 && ver[2] < 6683) ||
            (ver[0] == 12 && ver[1] == 0 && ver[2] == 6683 && ver[3] < 5002)
          )
        )
        {
          vuln = TRUE;
          info =
            '\n  Product           : Excel 2007' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 12.0.6683.5002' +
            '\n';
          hotfix_add_report(info, bulletin:bulletin, kb:"2827324");
        }

        share = hotfix_path2share(path:path);
        if (is_accessible_share(share:share))
        {
          check_file = "Oart.dll";
          old_report = hotfix_get_report();
          if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6683.5002", min_version:"12.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            fversion = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2007 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : 12.0.6683.5002' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2760585");
            vuln = TRUE;
          }
          NetUseDel(close:FALSE);

          check_file = "Oartconv.dll";
          old_report = hotfix_get_report();
          if (hotfix_check_fversion(path:path, file:check_file, version:"12.0.6683.5002", min_version:"12.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
             kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            fversion = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2007 SP3' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : 12.0.6683.5002' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2760591");
            vuln = TRUE;
          }
          NetUseDel(close:FALSE);
        }
      }
    }
    else if (ver[0] == 14)
    {
      # Office 2010 SP1 or Sp2
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && (office_sp == 1 || office_sp == 2))
      {
        if (
          (ver[0] == 14 && ver[1] == 0 && ver[2] < 7109) ||
          (ver[0] == 14 && ver[1] == 0 && ver[2] == 7109 && ver[3] < 5000)
        )
        {
          vuln = TRUE;
          info =
            '\n  Product           : Excel 2010' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 14.0.7109.5000' +
            '\n';
          hotfix_add_report(info, bulletin:bulletin, kb:"2826033");
        }
        share = hotfix_path2share(path:path);
        if (is_accessible_share(share:share))
        {
          check_file = "Oart.dll";
          old_report = hotfix_get_report();

          if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7108.5000", min_version:"14.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            fversion = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2010' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : 14.0.7108.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2826023");
            vuln = TRUE;
          }
          NetUseDel(close:FALSE);

          check_file = "Oartconv.dll";
          old_report = hotfix_get_report();
          if (hotfix_check_fversion(path:path, file:check_file, version:"14.0.7108.5000", min_version:"14.0.0.0") == HCF_OLDER)
          {
            file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
            kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
            fversion = get_kb_item(kb_name);

            info =
              '\n  Product           : Microsoft Office 2010' +
              '\n  File              : ' + path + '\\' + check_file +
              '\n  Installed version : ' + fversion +
              '\n  Fixed version     : 14.0.7108.5000' + '\n';

            hcf_report = '';
            hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2826035");
            vuln = TRUE;
          }
          NetUseDel(close:FALSE);
        }
      }
    }
    else if (ver[0] == 15)
    {
      # Office 2013
      if (
        (ver[0] == 15 && ver[1] == 0 && ver[2] < 4535) ||
        (ver[0] == 15 && ver[1] == 0 && ver[2] == 4535 && ver[3] < 1507)
      )
      {
        vuln = TRUE;
        info =
          '\n  Product           : Excel 2013' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 15.0.4535.1507' +
          '\n';
        hotfix_add_report(info, bulletin:bulletin, kb:"2827238");
      }

      share = hotfix_path2share(path:path);
      if (is_accessible_share(share:share))
      {
        check_file = "Oart.dll";
        old_report = hotfix_get_report();
        if (hotfix_check_fversion(path:path, file:check_file, version:"15.0.4535.1507", min_version:"15.0.0.0") == HCF_OLDER)
        {
          file = ereg_replace(pattern:"^[A-Za-z]:(.*)", string:path, replace:"\1\" + check_file);
          kb_name = "SMB/FileVersions/"+tolower(share-'$')+tolower(str_replace(string:file, find:"\", replace:"/"));
          fversion = get_kb_item(kb_name);

          info =
            '\n  Product           : Microsoft Office 2013' +
            '\n  File              : ' + path + '\\' + check_file +
            '\n  Installed version : ' + fversion +
            '\n  Fixed version     : 15.0.4535.1507' + '\n';

          hcf_report = '';
          hotfix_add_report(old_report + info, bulletin:bulletin, kb:"2817623");
          vuln = TRUE;
        }
        NetUseDel(close:FALSE);
      }
    }
  }
}

######################################################################
# Excel Viewer
######################################################################
version = '';
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelViewer/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:".", keep:FALSE);
    for (i = 0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    # Excel Viewer 2007 SP3.
    if (
      (ver[0] == 12 && ver[1] == 0 && ver[2] >= 6611) &&
      (
        (ver[0] == 12 && ver[1] == 0 && ver[2] < 6683) ||
        (ver[0] == 12 && ver[1] == 0 && ver[2] == 6683 && ver[3] < 5005)
      )
    )
    {
      vuln = TRUE;
      info =
        '\n  Product           : Excel Viewer' +
        '\n  File              : ' + path +
        '\n  Installed version : ' + version +
        '\n  Fixed version     : 12.0.6683.5005' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2827328");
      break;
    }
  }
}
if (!version)
{
  # Additional check if registry key is missing
  path = get_kb_item("SMB/Office/Excel/12.0/Path");

  kb = "2827328";
  if (
    hotfix_is_vulnerable(file:"Xlview.exe", version:"12.0.6683.5005", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
}

######################################################################
# Microsoft Office Compatibility Pack
######################################################################
version = '';
installs = get_kb_list("SMB/Office/ExcelCnv/*/ProductPath");
if (!isnull(installs))
{
  foreach install (keys(installs))
  {
    version = install - 'SMB/Office/ExcelCnv/' - '/ProductPath';
    path = installs[install];
    if (isnull(path)) path = "n/a";

    ver = split(version, sep:".", keep:FALSE);
    for (i = 0; i < max_index(ver); i++)
      ver[i] = int(ver[i]);

    if (
      (ver[0] == 12 && ver[1] == 0 && ver[2] < 6683) ||
      (ver[0] == 12 && ver[1] == 0 && ver[2] == 6683 && ver[3] < 5002)
    )
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6683.5002' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2827326");
    }
  }
}
if (!version)
{
  # Additional check if registry key is missing
  path = get_kb_item("SMB/Office/Excel/12.0/Path");

  kb = "2827326";
  if (
    hotfix_is_vulnerable(file:"Excelcnv.exe", version:"12.0.6683.5002", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)
  ) vuln = TRUE;
}

if (info || vuln)
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
