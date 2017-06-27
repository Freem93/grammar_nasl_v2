#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80497);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/02/14 05:40:10 $");

  script_cve_id("CVE-2015-0011");
  script_bugtraq_id(71960);
  script_osvdb_id(116953);
  script_xref(name:"MSFT", value:"MS15-008");

  script_name(english:"MS15-008: Vulnerability in Windows Kernel-Mode Driver Could Allow Elevation of Privilege (3019215)");
  script_summary(english:"Checks the version of Mrxdav.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability in the WebDAV kernel-mode driver due to a failure to
properly validate and enforce impersonation levels. This allows a
local attacker to bypass impersonation-level security and gain
elevated privileges, including the ability to intercept and alter
WebDAV requests.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-008");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");

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

bulletin = 'MS15-008';
kb = '3019215';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"Mrxdav.sys", version:"6.3.9600.17560", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"Mrxdav.sys", version:"6.2.9200.21317", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", file:"Mrxdav.sys", version:"6.2.9200.17219", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mrxdav.sys", version:"6.1.7601.22913", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Mrxdav.sys", version:"6.1.7601.18706", min_version:"6.1.7600.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mrxdav.sys", version:"6.0.6002.23581", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mrxdav.sys", version:"6.0.6002.19273", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mrxdav.sys", version:"5.2.3790.5508", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
