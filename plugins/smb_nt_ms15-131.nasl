#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87260);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/08 15:07:20 $");

  script_cve_id(
    "CVE-2015-6040",
    "CVE-2015-6118",
    "CVE-2015-6122",
    "CVE-2015-6124",
    "CVE-2015-6172",
    "CVE-2015-6177"
  );
  script_bugtraq_id(
    78543,
    78546,
    78547,
    78548,
    78549,
    78550
  );
  script_osvdb_id(
    131335,
    131336,
    131337,
    131338,
    131339,
    131340
  );
  script_xref(name:"MSFT", value:"MS15-131");
  script_xref(name:"IAVA", value:"2015-A-0300");

  script_name(english:"MS15-131: Security Update for Microsoft Office to Address Remote Code Execution (3116111)");
  script_summary(english:"Checks the Office, SharePoint, and OWA versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Word, Word
Viewer, Excel, Excel Viewer, or Microsoft Office Compatibility Pack
installed that is affected by multiple remote code execution
vulnerabilities :

  - Multiple memory corruption issues exist due to improper
    handling of objects in memory. A remote attacker can
    exploit these issues by convincing a user to open a 
    specially crafted file in an affected version of Office,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-6040,
    CVE-2015-6118, CVE-2015-6122, CVE-2015-6124,
    CVE-2015-6177)

  - A remote code execution vulnerability exists due to
    improper parsing of email messages. A remote attacker
    can exploit this vulnerability by convincing a user to
    open or preview a specially crafted email message,
    resulting in the execution of arbitrary code in the
    context of the current user. (CVE-2015-6172)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-131");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
2013 RT, 2016, Word, Word Viewer, Excel, Excel Viewer, and Microsoft
Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_owa_installed.nbin" , "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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
include("install_func.inc");

global_var bulletin, vuln;

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-131';
kbs = make_list(
  3085528,  # Office 2010 SP2
  3085549,  # Office 2007 SP3
  3101532,  # Office 2010 SP2
  3114342,  # Office 2013 SP1 / RT SP1
  3114382,  # Office 2016
  3114403,  # Office 2010 SP2
  3114415,  # Office 2010 SP2
  3114422,  # Office 2007 SP3
  3114425,  # Office 2007 SP3
  3114431,  # Office Compatibility Pack SP3
  3114433,  # Excel Viewer
  3114457,  # Office Compatibility Pack SP3
  3114458,  # Office 2007 SP3
  3114479   # Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");
registry_init();

# Generic Office Checks
function perform_office_checks()
{
  local_var office_vers, office_sp, path;
  office_vers = hotfix_check_office_version();
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"12.0"), value:"Microsoft Shared\Office12");
      if (
        hotfix_check_fversion(file:"mso.dll",       version: "12.0.6739.5000" , path:path, bulletin:bulletin, kb:"3114425", product:"Microsoft Office 2007 SP3") == HCF_OLDER ||
        hotfix_check_fversion(file:"msptls.dll",    version: "12.0.6739.5000" , path:path, bulletin:bulletin, kb:"3085549", product:"Microsoft Office 2007 SP3") == HCF_OLDER
      )
        vuln = TRUE;
    }
  }

  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (
        hotfix_check_fversion(file:"msptls.dll",   version: "14.0.7164.5000", path:path, bulletin:bulletin, kb:"3085528", product:"Microsoft Office 2010 SP2") == HCF_OLDER ||
        hotfix_check_fversion(file:"wwlibcxm.dll", version: "14.0.7164.5001", path:path, bulletin:bulletin, kb:"3114403", product:"Microsoft Office 2010 SP2") == HCF_OLDER
      )
        vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, word_checks, word_vwr_checks, vwr_checks, compat_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Excel Checks
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6739.5000", "kb", "3114422"),
    "14.0", make_array("sp", 2, "version", "14.0.7164.5000", "kb", "3114415")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6740.5000", "kb", "3114458"),
    "14.0", make_array("sp", 2, "version", "14.0.7164.5001", "kb", "3101532"),
    "15.0", make_array("sp", 1, "version", "15.0.4779.1001", "kb", "3114342"),
    "16.0", make_nested_list(
       make_array("sp", 0, "version", "16.0.4312.1001", "channel", "MSI", "kb", "3114382"),
       make_array("sp", 0, "version", "16.0.6001.1043", "channel", "Current", "kb", "3114382")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer  KB: 3114479
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if(!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8422.0", "kb", "3114479")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;
  }

  ######################################################################
  # Excel Viewer KB: 3114433
  ######################################################################
  vwr_checks = make_array(
    "12.0", make_array("version", "12.0.6739.5000", "kb", "3114433")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:vwr_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Excel Compatibility pack  KB: 3114431
  ######################################################################
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6739.5000", "kb", "3114431")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Compatibility pack   KB: 3114457
  ######################################################################
  installs = get_kb_list("SMB/Office/WordCnv/*/ProductPath");
  foreach install (keys(installs))
  {
    path = installs[install];
    path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
    if(hotfix_check_fversion(path:path, file:"wordcnv.dll",  version:"12.0.6740.5000", kb: "3114457", bulletin:bulletin, min_version:"12.0.0.0", product:"Microsoft Office Compatibility Pack") == HCF_OLDER)
      vuln = TRUE;
  }
}

perform_office_checks();
perform_office_product_checks();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
