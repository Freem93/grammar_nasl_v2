#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86366);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id("CVE-2015-2515", "CVE-2015-2548");
  script_bugtraq_id(76981, 76989);
  script_osvdb_id(128806, 128807);
  script_xref(name:"MSFT", value:"MS15-109");
  script_xref(name:"IAVA", value:"2015-A-0245");

  script_name(english:"MS15-109: Security Update for Windows Shell to Address Remote Code Execution (3096443)");
  script_summary(english:"Checks the version of shell32.dll and tipband.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by the following vulnerabilities :

  - A remote code execution vulnerability exists in the
    Windows shell due to improper handling of objects in
    memory. A remote attacker can exploit this vulnerability
    by convincing a user to open a specially crafted toolbar
    object, resulting in the execution of arbitrary code in
    the context of the current user. (CVE-2015-2515)

  - A privilege escalation vulnerability exists in the
    Microsoft Tablet Input Band due to improper handling of
    objects in memory. A remote attacker can exploit this
    vulnerability to gain the same user rights as the
    current user by convincing a user to visit a specially
    crafted website. (CVE-2015-2548)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-109");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS15-109';
kbs = make_list('3080446', '3096443', '3093513','3097617');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"shell32.dll", version:"10.0.10240.16542", dir:"\system32", bulletin:bulletin, kb:'3097617') ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"shell32.dll", version:"6.3.9600.18038", dir:"\system32", bulletin:bulletin, kb:"3080446") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"shell32.dll", version:"6.2.9200.21578", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3080446") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"shell32.dll", version:"6.2.9200.17464", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3080446") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"shell32.dll", version:"6.1.7601.23155", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3080446") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"shell32.dll", version:"6.1.7601.18952", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3080446") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"tipband.dll", version:"6.1.7601.23187", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3093513") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"tipband.dll", version:"6.1.7601.18984", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3093513") ||


  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.23767", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3080446") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"shell32.dll", version:"6.0.6002.19459", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3080446") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"tipband.dll", version:"6.0.6002.23793", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3093513") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"tipband.dll", version:"6.0.6002.19483", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3093513")
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
