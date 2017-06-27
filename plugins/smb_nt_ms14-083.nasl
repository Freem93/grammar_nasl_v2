#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79832);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2014-6360", "CVE-2014-6361");
  script_bugtraq_id(71500, 71501);
  script_osvdb_id(115584, 115585);
  script_xref(name:"MSFT", value:"MS14-083");

  script_name(english:"MS14-083: Vulnerabilities in Microsoft Excel Could Allow Remote Code Execution (3017347)");
  script_summary(english:"Checks the Excel versions.");

  script_set_attribute(attribute:"synopsis", value:
"The Microsoft Office component installed on the remote host is
affected by multiple remote code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Excel or Office
Compatibility Pack that is affected by multiple remote code execution
vulnerabilities due to Microsoft Excel improperly handling objects in
memory. A remote attacker can exploit these vulnerabilities by
convincing a user to open a specially crafted Office file, resulting
in execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/en-us/library/security/ms14-083.aspx");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Excel 2007, Excel 2010,
Excel 2013, and Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = "MS14-083";
kbs = make_list(
  2910902,
  2910929,
  2920790,
  2920791,
  2984942
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
          (ver[0] == 12 && ver[1] == 0 && ver[2] < 6712) ||
          (ver[0] == 12 && ver[1] == 0 && ver[2] == 6712 && ver[3] < 5000)
        )
        {
          vuln = TRUE;
          info =
            '\n  Product           : Excel 2007' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 12.0.6712.5000' +
            '\n';
          hotfix_add_report(info, bulletin:bulletin, kb:"2984942");
        }
      }
    }
    else if (ver[0] == 14)
    {
      # Office 2010 SP2
      office_sp = get_kb_item("SMB/Office/2010/SP");
      if (!isnull(office_sp) && office_sp == 2)
      {
        if (
          (ver[0] == 14 && ver[1] == 0 && ver[2] < 7140) ||
          (ver[0] == 14 && ver[1] == 0 && ver[2] == 7140 && ver[3] < 5000)
        )
        {
          vuln = TRUE;
          info =
            '\n  Product           : Excel 2010' +
            '\n  File              : ' + path +
            '\n  Installed version : ' + version +
            '\n  Fixed version     : 14.0.7140.5000' +
            '\n';
          hotfix_add_report(info, bulletin:bulletin, kb:"2910902");
        }
      }
    }
    else if (ver[0] == 15)
    {
      # Office 2013
      if (
        (ver[0] == 15 && ver[1] == 0 && ver[2] < 4675) ||
        (ver[0] == 15 && ver[1] == 0 && ver[2] == 4675 && ver[3] < 1000)
      )
      {
        vuln = TRUE;
        info =
          '\n  Product           : Excel 2013' +
          '\n  File              : ' + path +
          '\n  Installed version : ' + version +
          '\n  Fixed version     : 15.0.4675.1000' +
          '\n';
        hotfix_add_report(info, bulletin:bulletin, kb:"2910929");
      }
    }
  }
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
      (ver[0] == 12 && ver[1] == 0 && ver[2] < 6713) ||
      (ver[0] == 12 && ver[1] == 0 && ver[2] == 6713 && ver[3] < 5000)
    )
    {
      info =
        '\n  Product           : 2007 Office system and the Office Compatibility Pack' +
        '\n  File              : '+ path +
        '\n  Installed version : '+ version +
        '\n  Fixed version     : 12.0.6713.5000' +
        '\n';
      hotfix_add_report(info, bulletin:bulletin, kb:"2920790");
    }
  }
}

# Check for 2920791
installs = get_kb_list("SMB/Office/ExcelViewer/*/ProductPath");
if(!isnull(installs)) 
{
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:"\\[A-Za-z.]+$", replace:"\", string:path);
    vuln = hotfix_is_vulnerable(file:"xlview.exe", version:"12.0.6716.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:"2920791");
    if(vuln) break;
  }
}

if (!version)
{
  # Additional check if registry key is missing
  path = get_kb_item("SMB/Office/Excel/12.0/Path");

  kb = "2920790";
  if (
    hotfix_is_vulnerable(file:"excelcnv.exe", version:"12.0.6713.5000", min_version:"12.0.0.0", path:path, bulletin:bulletin, kb:kb)
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
