#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87261);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2015-6128", "CVE-2015-6132", "CVE-2015-6133");
  script_bugtraq_id(78496, 78614, 78615);
  script_osvdb_id(131035, 131036, 131342, 131343);
  script_xref(name:"MSFT", value:"MS15-132");
  script_xref(name:"IAVB", value:"2015-B-0143");

  script_name(english:"MS15-132: Security Update for Microsoft Windows to Address Remote Code Execution (3116162)");
  script_summary(english:"Checks the file versions of the affected files.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities due to improper input validation when libraries are
linked. A remote attacker can exploit these vulnerabilities by
convincing a user to open a specially crafted file, resulting in the
execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-132");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Office OLE Multiple DLL Side Loading Vulnerabilities');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/12/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");
  
  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-132';
kbs = make_list(
    "3116162",
    "3116900",
    "3116869",
    "3108371",
    "3108381",
    "3108347");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"authui.dll", version:"10.0.10586.20", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3116900") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"authui.dll", version:"10.0.10240.16603", dir:"\system32", bulletin:bulletin, kb:"3116869") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntdll.dll", version:"10.0.10586.20", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3116900") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"ntdll.dll", version:"10.0.10240.16603", dir:"\system32", bulletin:bulletin, kb:"3116869") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"authui.dll", version:"6.3.9600.18111", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3108347") ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ntdll.dll", version:"6.3.9600.18146", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"authui.dll", version:"6.2.9200.21678", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3108347") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"authui.dll", version:"6.2.9200.17561", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3108347") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdll.dll", version:"6.2.9200.21703", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ntdll.dll", version:"6.2.9200.17581", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"comsvcs.dll", version:"2001.12.8531.23278", min_version:"2001.12.8531.22000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"comsvcs.dll", version:"2001.12.8531.19062", min_version:"2001.12.8530.16000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"els.dll", version:"6.1.7601.23259", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3108371") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"els.dll", version:"6.1.7601.19054", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3108371") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"comsvcs.dll", version:"2001.12.6932.23847", min_version:"2001.12.6932.23000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"comsvcs.dll", version:"2001.12.6932.19537", min_version:"2001.12.6932.18000", dir:"\system32", bulletin:bulletin, kb:"3108381") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"els.dll", version:"6.0.6002.23843", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3108371") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"els.dll", version:"6.0.6002.19533", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3108371")
)
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
