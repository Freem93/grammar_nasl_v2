#
# (C) Tenable Network Security, Inc.
#
include("compat.inc");
if (description)
{
  script_id(84055);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");
  
  script_cve_id(
    "CVE-2015-1759",
    "CVE-2015-1760",
    "CVE-2015-1770"
  );
  script_bugtraq_id(
    75014,
    75015,
    75016
  );
  script_osvdb_id(
    123078,
    123079,
    123080
  );
  script_xref(name:"MSFT", value:"MS15-059");
  script_xref(name:"IAVB", value:"2015-B-0071");
  
  script_name(english:"MS15-059: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (3064949)");
  script_summary(english:"Checks the file versions to see if KB is installed.");
  
  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Office or Office Compatibility Pack installed
on the remote host is affected by multiple remote code execution
vulnerabilities due to a failure to properly handle objects in memory.
A remote attacker can exploit these vulnerabilities by convincing a
user to open a specially crafted Office file, resulting in execution
of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-059");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Office 2007, 2010, 2013,
and the Office Compatibility Pack.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office_compatibility_pack");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  
  script_family(english:"Windows : Microsoft Bulletins");
  
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
  
  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "office_installed.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");
  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("install_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-059';
kbs = make_list(
  "2863812",
  "2863817",
  "3039749",
  "3039782"
);
vuln = 0;

###################################################################################
# Main

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

office_versions = hotfix_check_office_version();

# KB 2863812 Office 2007 SP3
if (!empty_or_null(office_versions) && office_versions["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (office_sp == 3)
  {
    prod = "Microsoft Office 2007 SP3";
    kb   = "2863812";
    path = hotfix_get_officecommonfilesdir(officever:"12.0");
    path = hotfix_append_path(path:path, value:"\Microsoft Shared\TextConv");
    if (hotfix_check_fversion(file:"Wpft532.cnv", version:"2006.1200.6722.5000", min_version:"2006.1200.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
      vuln++;
  }
}

# KB 2863817 Office 2010 SP2
if (!empty_or_null(office_versions) && office_versions["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (office_sp == 2)
  {
    prod = "Microsoft Office 2010 SP2";
    kb   = "2863817";
    path = hotfix_get_officecommonfilesdir(officever:"14.0");
    path = hotfix_append_path(path:path, value:"\Microsoft Shared\TextConv");
    if (hotfix_check_fversion(file:"Wpft532.cnv", version:"2010.1400.7151.5000", min_version:"2010.1400.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
      vuln++;
  }
}

# KB 3039749 / 3039782 Office 2013 SP1
if (!empty_or_null(office_versions) && office_versions["15.0"])
{
  office_sp = get_kb_item("SMB/Office/2013/SP");
  if (office_sp == 1)
  {
    prod = "Microsoft Office 2013 SP1";
    kb   = "3039749";
    path = hotfix_get_officecommonfilesdir(officever:"15.0");
    path = hotfix_append_path(path:path, value:"\Microsoft Shared\TextConv");
    if (hotfix_check_fversion(file:"Wpft532.cnv", version:"2012.1500.4727.1000", min_version:"2012.1500.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
      vuln++;
    kb   = "3039782";
    path = hotfix_get_programfilesdirx86();
    path = hotfix_append_path(path:path, value:"\Microsoft Office\Office15");
    if (hotfix_check_fversion(file:"MSOSB.DLL", version:"15.0.4699.1000", min_version:"15.0.0.0", path:path, bulletin:bulletin, kb:kb, product:prod) == HCF_OLDER)
      vuln++;
  }
}

###################################################################################
# REPORT
if (vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, "affected");
}
