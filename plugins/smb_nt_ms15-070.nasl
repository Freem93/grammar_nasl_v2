#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84739);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id(
    "CVE-2015-2375",
    "CVE-2015-2376",
    "CVE-2015-2377",
    "CVE-2015-2378",
    "CVE-2015-2379",
    "CVE-2015-2380",
    "CVE-2015-2415",
    "CVE-2015-2424"
  );
  #script_bugtraq_id();
  script_osvdb_id(
    124598,
    124599,
    124600,
    124601,
    124602,
    124603,
    124604,
    124605
  );
  script_xref(name:"MSFT", value:"MS15-070");
  script_xref(name:"IAVA", value:"2015-A-0163");

  script_name(english:"MS15-070: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3072620)");
  script_summary(english:"Checks the Office and SharePoint versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Microsoft Office, Microsoft
Word, Microsoft Excel, Microsoft PowerPoint, SharePoint Server, or
Microsoft Office Compatibility Pack installed that is affected by
multiple vulnerabilities :

  - An ASLR bypass vulnerability exists in Microsoft Excel
    due to memory being released in an unintended manner. A
    remote attacker can exploit this by convincing a user to
    open a specially crafted Excel (.xls) file, allowing the
    attacker to more reliably predict the memory offsets of
    specific instructions in a given call stack. The
    attacker can then utilize this information to more
    easily exploit additional vulnerabilities.
    (CVE-2015-2375)

  - Multiple remote code execution vulnerabilities exist
    due to improper handling of objects in memory. A remote
    attacker can exploit these vulnerabilities by convincing
    a user to open a specially crafted file, resulting in
    the execution of arbitrary code in the context of the
    current user. (CVE-2015-2376, CVE-2015-2377,
    CVE-2015-2379, CVE-2015-2380, CVE-2015-2415,
    CVE-2015-2424)

  - A remote code execution vulnerability exists in
    Microsoft excel due to improper handling of the loading
    of dynamic link library (DLL) files. A remote attacker
    can exploit this vulnerability by placing a specially
    crafted DLL file in the user's current working directory
    and then convincing the user to launch a program
    designed to load the DLL, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2015-2378)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-070");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007. Office 2010,
Office 2013, Word 2007, Word 2010, Word 2013, Excel 2007, Excel 2010,
Excel 2013, PowerPoint 2007, PowerPoint 2010, PowerPoint 2013, Excel
Viewer, Word Viewer, Office Compatibility Pack, SharePoint Server
2007, SharePoint Server 2010, and SharePoint Server 2013.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:powerpoint");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:excel_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:sharepoint_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("office_installed.nasl", "microsoft_sharepoint_installed.nbin", "smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS15-070';
kbs = make_list(
  2837612, # SharePoint Server 2007 SP3
  2965208, # Office Compat Pack SP3
  2965209, # Excel Viewer 2007 SP3
  2965281, # Excel 2007 SP3
  2965283, # PowerPoint 2007 SP3
  3054861, # SharePoint Server 2013 SP1
  3054949, # Excel 2013 SP1
  3054958, # Word Viewer
  3054963, # PowerPoint 2010 SP2
  3054968, # SharePoint Server 2010 SP2
  3054971, # Office 2010 SP2
  3054973, # Word 2010 SP2
  3054981, # Excel 2010 SP2
  3054990, # Word 2013 SP1
  3054996, # Word 2007 SP3
  3054999  # PowerPoint 2013 SP1
);

######################################################################
# Main
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
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"12.0"), value:"Microsoft Office\Office12");
      if (hotfix_check_fversion(file:"ppcore.dll", version:"12.0.6726.5000", path:path, bulletin:bulletin, kb:"2965283", product:"PowerPoint 2007 SP3") == HCF_OLDER)
        vuln = TRUE;
    }
  }
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"Wwlib.dll", version:"14.0.7153.5002", path:path, bulletin:bulletin, kb:"3054971", product:"Microsoft Office 2010") == HCF_OLDER)
        vuln = TRUE;
    }
  }
}

function perform_office_product_checks()
{
  local_var excel_checks, ppt_checks, word_checks, excel_vwr_checks, compat_checks, word_vwr_checks;

  ######################################################################
  # Excel
  ######################################################################
  excel_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6723.5000", "kb", "2965281"),
    "14.0", make_array("sp", 2, "version", "14.0.7153.5000", "kb", "3054981"),
    "15.0", make_array("sp", 1, "version", "15.0.4737.1000", "kb", "3054949")
  );
  if (hotfix_check_office_product(product:"Excel", checks:excel_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint
  ######################################################################
  ppt_checks = make_array(
    "14.0", make_array("sp", 2, "version", "14.0.7138.5000", "kb", "3054963"),
    "15.0", make_array("sp", 1, "version", "15.0.4737.1003", "kb", "3054999")
  );
  if (hotfix_check_office_product(product:"PowerPoint", checks:ppt_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6726.5000", "kb", "3054996"),
    "14.0", make_array("sp", 2, "version", "14.0.7153.5002", "kb", "3054973"),
    "15.0", make_array("sp", 1, "version", "15.0.4737.1003", "kb", "3054990")
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # PowerPoint Viewer 2010
  # KB: 2956195 Fix Ver: 14.0.7149.5000
  ######################################################################
  excel_vwr_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6723.5000", "kb", "2965209")
  );
  if (hotfix_check_office_product(product:"ExcelViewer", display_name:"Excel Viewer", checks:excel_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
  compat_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6723.5000", "kb", "2965208")
  );
  if (hotfix_check_office_product(product:"ExcelCnv", display_name:"Office Compatibility Pack SP3", checks:compat_checks, bulletin:bulletin))
    vuln = TRUE;
  word_vwr_checks = make_array(
    "11.0", make_array("version", "11.0.8419.0", "kb", "3054958")
  );
  if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
    vuln = TRUE;
}

######################################################################
# SharePoint
######################################################################
function perform_sharepoint_checks()
{
  local_var sps_2007_path, sps_2007_sp, sps_2007_edition;
  local_var sps_2010_path, sps_2013_path, sps_2010_sp, sps_2013_sp, sps_2010_edition, sps_2013_edition;
  local_var installs, install, sp, path;
  local_var share, name, port, login, pass, domain, rc;
  local_var js, file, timestamp, kb, info;

  # Get installs of SharePoint
  sps_2007_path = NULL;
  sps_2010_path = NULL;
  sps_2013_path = NULL;
  sp = NULL;

  installs = get_installs(app_name:"Microsoft SharePoint Server");
  foreach install (installs[1])
  {
    if (install["Product"] == "2007")
    {
      sps_2007_path = install["path"];
      sps_2007_sp = install["SP"];
      sps_2007_edition = install["Edition"];
    }
    if (install['Product'] == "2010")
    {
      sps_2010_path = install['path'];
      sps_2010_sp = install['SP'];
      sps_2010_edition = install['Edition'];
    }
    else if (install['Product'] == "2013")
    {
      sps_2013_path = install['path'];
      sps_2013_sp = install['SP'];
      sps_2013_edition = install['Edition'];
    }
  }

  ######################################################################
  # SharePoint Server 2007 SP3 - Excel Services
  # KB: 2837612 File: xlsrv.dll Fix Ver: 12.0.6723.5000
  ######################################################################
  if (sps_2007_path && sps_2007_sp == "3" && sps_2007_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2007_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"12.0.6723.5000", path:path, bulletin:bulletin, kb:"2837612", product:"Office SharePoint Server 2007 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2010 SP2 - Excel Services
  # KB: 3054968 File: xlsrv.dll Fix Ver: 14.0.7153.5000
  ######################################################################
  if (sps_2010_path && sps_2010_sp == "2" && sps_2010_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2010_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"14.0.7153.5000", path:path, bulletin:bulletin, kb:"3054968", product:"Office SharePoint Server 2010 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }

  ######################################################################
  # SharePoint Server 2013 SP1 - Excel Services
  # KB: 3054861 File: xlsrv.dll Fix Ver: 15.0.4737.1000
  ######################################################################
  if (sps_2013_path && sps_2013_sp == "1" && sps_2013_edition == "Server")
  {
    path = hotfix_append_path(path:sps_2013_path, value:"Bin");
    if (hotfix_check_fversion(file:"xlsrv.dll", version:"15.0.4737.1000", path:path, bulletin:bulletin, kb:"3054861", product:"Office SharePoint Server 2013 Excel Services") == HCF_OLDER)
      vuln = TRUE;
  }
}

perform_office_checks();
perform_office_product_checks();
perform_sharepoint_checks();

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
