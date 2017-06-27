#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92839);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id(
    "CVE-2016-3313",
    "CVE-2016-3315",
    "CVE-2016-3316",
    "CVE-2016-3317",
    "CVE-2016-3318"
  );
  script_bugtraq_id(
    92289,
    92294,
    92300,
    92303,
    92308
  );
  script_osvdb_id(
    142738,
    142739,
    142740,
    142741,
    142742
  );
  script_xref(name:"MSFT", value:"MS16-099");
  script_xref(name:"IAVA", value:"2016-A-0203");

  script_name(english:"MS16-099: Security Update for Microsoft Office (3177451)");
  script_summary(english:"Checks the file versions.");

  script_set_attribute(attribute:"synopsis",value:
"An application installed on the remote Windows host is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description",value:
"The Microsoft Office application installed on the remote Windows host
is missing a security update. It is, therefore, affected by multiple
vulnerabilities :

  - Multiple memory corruption issues exist in Microsoft
    Office software due to improper handling of objects in
    memory. An unauthenticated, remote attacker can exploit
    these issues, by convincing a user to open a specially
    crafted file, to execute arbitrary code in the context
    of the current user. (CVE-2016-3313, CVE-2016-3316,
    CVE-2016-3317, CVE-2016-3318)

  - An information disclosure vulnerability exists in
    Microsoft OneNote due to an unspecified flaw. An
    unauthenticated, remote attacker can exploit this, by
    convincing a user to open a specially crafted OneNote
    file, to disclose sensitive memory contents.
    (CVE-2016-3315)");
  script_set_attribute(attribute:"see_also",value:"https://technet.microsoft.com/library/security/MS16-099");
  script_set_attribute(attribute:"solution",value:
"Microsoft has released a set of patches for Microsoft Office 2007,
2010, 2013, 2013 RT, and 2016; Microsoft Word 2007, 2010, 2013, 2013
RT, and 2016; Microsoft OneNote 2007, 2010, 2013, 2013 RT, and 2016;
Microsoft Outlook 2007, 2010, 2013, and 2016; and Word Viewer.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2016/08/09");
  script_set_attribute(attribute:"patch_publication_date",value:"2016/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/10");

  script_set_attribute(attribute:"plugin_type",value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:onenote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:word_viewer");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:outlook");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies(
    "office_installed.nasl",
    "smb_hotfixes.nasl",
    "ms_bulletin_checks_possible.nasl"
  );
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

bulletin = 'MS16-099';
kbs = make_list(
  '3114340', # Office 2013 SP1
  '3114400', # Office 2010 SP2
  '3114442', # Office 2007 SP3
  '3114456', # OneNote 2007 SP3
  '3114869', # Office 2010 SP2
  '3114885', # OneNote 2010 SP2
  '3114893', # Office 2007 SP3
  '3114981', # Outlook 2007 SP3
  '3115256', # OneNote 2013 SP1
  '3115415', # Office 2016
  '3115419', # OneNote 2016
  '3115427', # Office 2013 SP1
  '3115439', # Word 2016
  '3115440', # Outlook 2016
  '3115449', # Word 2013 SP1
  '3115452', # Outlook 2013 SP1
  '3115465', # Word 2007 SP3
  '3115468', # Office 2010 SP2
  '3115471', # Word 2010 SP2
  '3115474', # Outlook 2010 SP2
  '3115479', # Word Viewer
  '3115480'  # Word Viewer
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);

# Get path information for Windows.
windir = hotfix_get_systemroot();
if (isnull(windir)) exit(1, "Failed to determine the location of %windir%.");

vuln = FALSE;

function perform_office_checks()
{
  local_var office_vers, office_sp, common_path, path, prod, kb;
  office_vers = hotfix_check_office_version();

  ######################################################################
  # Office 2007 Checks
  ######################################################################
  if (office_vers["12.0"])
  {
    office_sp = get_kb_item("SMB/Office/2007/SP");
    if (!isnull(office_sp) && office_sp == 3)
    {
      prod = "Microsoft Office 2007 SP3";
      common_path = hotfix_get_officecommonfilesdir(officever:"12.0");

      path = hotfix_append_path(path:common_path, value:"\Microsoft Shared\GRPHFLT");
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2006.1200.6737.5000", min_version:"2006.1200.0.0", path:path, bulletin:bulletin, kb:"3114442", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office12");
      if (hotfix_check_fversion(file:"mso.dll", version:"12.0.6754.5000" , path:path, bulletin:bulletin, kb:"3114893", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # Office 2010 Checks
  ######################################################################
  if (office_vers["14.0"])
  {
    office_sp = get_kb_item("SMB/Office/2010/SP");
    if (!isnull(office_sp) && office_sp == 2)
    {
      prod = "Microsoft Office 2010 SP2";
      common_path = hotfix_get_officecommonfilesdir(officever:"14.0");

      path = hotfix_append_path(path:common_path, value:"\Microsoft Shared\GRPHFLT");
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2010.1400.7163.5000", min_version:"2010.1400.0.0", path:path, bulletin:bulletin, kb:"3114400", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office14");
      if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7172.5000", path:path, bulletin:bulletin, kb:"3114869", product:prod) == HCF_OLDER)
        vuln = TRUE;

      if ( "64" >< get_kb_item("SMB/Office/14.0/Bitness"))
      {
        path = hotfix_append_path(path:hotfix_get_commonfilesdirx86(), value:"Microsoft Shared\Office14");
        if (hotfix_check_fversion(file:"mso.dll", version:"14.0.7172.5000", path:path, bulletin:bulletin, kb:"3114869", product:prod) == HCF_OLDER)
          vuln = TRUE;
      }

      # wwlibcxm.dll only exists if KB2428677 is installed
      path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"14.0"), value:"Microsoft Office\Office14");
      if (hotfix_check_fversion(file:"wwlibcxm.dll", version:"14.0.7172.5000", path:path, bulletin:bulletin, kb:"3115468", product:prod) == HCF_OLDER)
        vuln = TRUE;
    }
  }

  ######################################################################
  # Office 2013 Checks
  ######################################################################
  if (office_vers["15.0"])
  {
    office_sp = get_kb_item("SMB/Office/2013/SP");
    if (!isnull(office_sp) && int(office_sp) == 1)
    {
      prod = "Microsoft Office 2013 SP1";
      common_path = hotfix_get_officecommonfilesdir(officever:"15.0");

      path = hotfix_append_path(path:common_path, value:"\Microsoft Shared\GRPHFLT");
      if (hotfix_check_fversion(file:"epsimp32.flt", version:"2012.1500.4775.1000", min_version:"2012.1500.0.0", path:path, bulletin:bulletin, kb:"3114340", product:prod) == HCF_OLDER)
        vuln = TRUE;

      path = hotfix_append_path(path:common_path, value:"Microsoft Shared\Office15");
      if (hotfix_check_fversion(file:"mso.dll", version: "15.0.4849.1000", path:path, bulletin:bulletin, kb:"3115427", product:prod) == HCF_OLDER)
        vuln = TRUE;

      if ( "64" >< get_kb_item("SMB/Office/15.0/Bitness"))
      {
        path = hotfix_append_path(path:hotfix_get_commonfilesdirx86(), value:"Microsoft Shared\Office15");
        if (hotfix_check_fversion(file:"mso.dll", version:"15.0.4849.1000", path:path, bulletin:bulletin, kb:"3115427", product:prod) == HCF_OLDER)
          vuln = TRUE;
      }
    }
  }

  ######################################################################
  # Office 2016 Checks
  ######################################################################
  if (office_vers["16.0"])
  {
    office_sp = get_kb_item("SMB/Office/2016/SP");
    if (!isnull(office_sp) && int(office_sp) == 0)
    {
      prod = "Microsoft Office 2016";
      path = hotfix_append_path(path:hotfix_get_officecommonfilesdir(officever:"16.0"), value:"Microsoft Shared\Office16");
      if (
        hotfix_check_fversion(file:"mso.dll", version:"16.0.4417.1000", channel:"MSI", channel_product:"Office", path:path, bulletin:bulletin, kb:"3115415", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.6701.1036", channel:"Deferred", channel_version:"1602", channel_product:"Office", path:path, bulletin:bulletin, kb:"3115415", product:prod) == HCF_OLDER ||
        hotfix_check_fversion(file:"mso.dll", version:"16.0.7127.1019", channel:"Current", channel_product:"Office", path:path, bulletin:bulletin, kb:"3115415", product:prod) == HCF_OLDER
      )
        vuln = TRUE;

      if ( "64" >< get_kb_item("SMB/Office/16.0/Bitness"))
      {
        path = hotfix_append_path(path:hotfix_get_officeprogramfilesdir(officever:"16.0"), value:"Microsoft Office\root\VFS\ProgramFilesCommonX86\Microsoft Shared\OFFICE16");
        if (
          hotfix_check_fversion(file:"mso.dll", version:"16.0.4417.1000", channel:"MSI", channel_product:"Office", path:path, bulletin:bulletin, kb:"3115415", product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:"mso.dll", version:"16.0.6701.1036",  channel:"Deferred", channel_version:"1602", channel_product:"Office", path:path, bulletin:bulletin, kb:"3115415", product:prod) == HCF_OLDER ||
          hotfix_check_fversion(file:"mso.dll", version:"16.0.7127.1019", channel:"Current", channel_product:"Office", path:path, bulletin:bulletin, kb:"3115415", product:prod) == HCF_OLDER
        )
          vuln = TRUE;
      }
    }
  }
}

function perform_office_product_checks()
{
  local_var word_checks, onenote_checks, outlook_checks, word_vwr_checks;

  local_var installs, install, path; # For DLL checks

  ######################################################################
  # Word Checks
  ######################################################################
  word_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6754.5000", "kb", "3115465"),
    "14.0", make_array("sp", 2, "version", "14.0.7172.5000", "kb", "3115471"),
    "15.0", make_array("sp", 1, "version", "15.0.4849.1000", "kb", "3115449"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4417.1000", "channel", "MSI", "kb", "3115439"),
      make_array("sp", 0, "version", "16.0.6001.1087", "channel", "Deferred", "kb", "3115439"),
      make_array("sp", 0, "version", "16.0.6741.2063", "channel", "Deferred", "channel_version", "1602", "kb", "3115439"),
      make_array("sp", 0, "version", "16.0.6965.2076", "channel", "First Release for Deferred", "kb", "3115439"),
      make_array("sp", 0, "version", "16.0.7167.2036", "channel", "Current", "kb", "3115439")
    )
  );
  if (hotfix_check_office_product(product:"Word", checks:word_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # OneNote Checks
  ######################################################################
  onenote_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6735.5000", "kb", "3114456"),
    "14.0", make_array("sp", 2, "version", "14.0.7162.5000", "kb", "3114885"),
    "15.0", make_array("sp", 1, "version", "15.0.4831.1000", "kb", "3115256"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4405.1000", "channel", "MSI", "kb", "3115419"),
      make_array("sp", 0, "version", "16.0.6001.1087", "channel", "Deferred", "kb", "3115419"),
      make_array("sp", 0, "version", "16.0.6741.2063", "channel", "Deferred", "channel_version", "1602", "kb", "3115419"),
      make_array("sp", 0, "version", "16.0.6965.2076", "channel", "First Release for Deferred", "kb", "3115419"),
      make_array("sp", 0, "version", "16.0.7167.2036", "channel", "Current", "kb", "3115419")
    )
  );
  if (hotfix_check_office_product(product:"OneNote", checks:onenote_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Outlook Checks
  ######################################################################
  outlook_checks = make_array(
    "12.0", make_array("sp", 3, "version", "12.0.6753.5000", "kb", "3114981"),
    "14.0", make_array("sp", 2, "version", "14.0.7172.5000", "kb", "3115474"),
    "15.0", make_array("sp", 1, "version", "15.0.4849.1000", "kb", "3115452"),
    "16.0", make_nested_list(
      make_array("sp", 0, "version", "16.0.4417.1000", "channel", "MSI", "kb", "3115440"),
      make_array("sp", 0, "version", "16.0.6001.1087", "channel", "Deferred", "kb", "3115440"),
      make_array("sp", 0, "version", "16.0.6741.2063", "channel", "Deferred", "channel_version", "1602", "kb", "3115440"),
      make_array("sp", 0, "version", "16.0.6965.2076", "channel", "First Release for Deferred", "kb", "3115440"),
      make_array("sp", 0, "version", "16.0.7167.2036", "channel", "Current", "kb", "3115440")
    )
  );
  if (hotfix_check_office_product(product:"Outlook", checks:outlook_checks, bulletin:bulletin))
    vuln = TRUE;

  ######################################################################
  # Word Viewer
  ######################################################################
  installs = get_kb_list("SMB/Office/WordViewer/*/ProductPath");
  if (!isnull(installs))
  {
    word_vwr_checks = make_array(
      "11.0", make_array("version", "11.0.8433.0", "kb", "3115480")
    );
    if (hotfix_check_office_product(product:"WordViewer", display_name:"Word Viewer", checks:word_vwr_checks, bulletin:bulletin))
      vuln = TRUE;

    foreach install (keys(installs))
    {
      path = installs[install];
      path = ereg_replace(pattern:'^(.+)\\\\[^\\\\]+\\.exe$', replace:"\1\", string:path, icase:TRUE);
      if(hotfix_check_fversion(path:path, file:"mso.dll", version:"11.0.8433.0", kb:"3115479", bulletin:bulletin, min_version:"11.0.0.0", product:"Microsoft Word Viewer") == HCF_OLDER)
        vuln = TRUE;
    }
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
