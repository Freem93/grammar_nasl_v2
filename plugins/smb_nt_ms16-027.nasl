#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89750);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/18 20:50:58 $");

  script_cve_id("CVE-2016-0098", "CVE-2016-0101");
  script_bugtraq_id(84089, 84111);
  script_osvdb_id(135529, 135530);
  script_xref(name:"MSFT", value:"MS16-027");
  script_xref(name:"IAVA", value:"2016-A-0064");

  script_name(english:"MS16-027: Security Update for Windows Media to Address Remote Code Execution (3143146)");
  script_summary(english:"Checks the version of wmp.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple remote code execution
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Windows Media Player installed on the remote
host is affected by multiple remote code execution vulnerabilities due
to improper handling of resources in the media library. An
unauthenticated, remote attacker can exploit these vulnerabilities by
convincing a user to open specially crafted media content, resulting
in the execution of arbitrary code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-027");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2008 R2, 2012,
8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_player");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

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

bulletin = 'MS16-027';
kbs = make_list("3138910", "3138962", "3140745", "3140768");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Server 2012, but not 8
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"wmp.dll", version:"12.0.10586.162", min_version:"12.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3140768") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"wmp.dll", version:"12.0.10240.16724", min_version:"12.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3140745") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mfds.dll", version:"12.0.9600.18228", min_version:"12.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3138910") ||
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"wmp.dll", version:"12.0.9600.18229", min_version:"12.0.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3138962") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mfds.dll", version:"12.0.9200.21766", min_version:"12.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3138910") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mfds.dll", version:"12.0.9200.17647", min_version:"12.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3138910") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"wmp.dll", version:"12.0.9200.21767", min_version:"12.0.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3138962") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"wmp.dll", version:"12.0.9200.17648", min_version:"12.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3138962") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mfds.dll", version:"12.0.7601.23346", min_version:"12.0.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3138910") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mfds.dll", version:"12.0.7601.19145", min_version:"12.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3138910") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"wmp.dll", version:"12.0.7601.23348", min_version:"12.0.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3138962") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"wmp.dll", version:"12.0.7601.19148", min_version:"12.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:"3138962")
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
