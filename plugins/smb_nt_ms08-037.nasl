#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33441);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2008-1447", "CVE-2008-1454");
 script_bugtraq_id(30131, 30132);
 script_osvdb_id(46777, 46778);
 script_xref(name:"CERT", value:"800113");
 script_xref(name:"MSFT", value:"MS08-037");
 script_xref(name:"IAVA", value:"2008-A-0045");

 script_name(english:"MS08-037: Vulnerabilities in DNS Could Allow Spoofing (953230)");
 script_summary(english:"Determines the presence of update 953230");

 script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to DNS spoofing attacks.");
 script_set_attribute(attribute:"description", value:
"Flaws in the remote DNS library may let an attacker send malicious DNS
responses to DNS requests made by the remote host, thereby spoofing or
redirecting internet traffic from legitimate locations.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-037");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released patches for Windows 2000, XP, and 2003
Server.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/07/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/07/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-037';
dnsapi_kb = '951748';
dnsexe_kb = '951746';

kbs = make_list(dnsapi_kb, dnsexe_kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName") )
	is_dns_svr = TRUE;
else
	is_dns_svr = FALSE;

if (
  (is_dns_svr && hotfix_is_vulnerable(os:"6.0", sp:1, file:"dns.exe", version:"6.0.6001.18081", dir:"\system32", bulletin:bulletin, kb:dnsexe_kb)) ||
  (is_dns_svr && hotfix_is_vulnerable(os:"6.0", sp:1, file:"dns.exe", version:"6.0.6001.22192", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:dnsexe_kb)) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"dnsapi.dll", version:"5.2.3790.4318", dir:"\system32", bulletin:bulletin, kb:dnsapi_kb) ||
  (is_dns_svr && hotfix_is_vulnerable(os:"5.2", sp:2, file:"dns.exe", version:"5.2.3790.4318", dir:"\system32", bulletin:bulletin, kb:dnsexe_kb)) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"dnsapi.dll", version:"5.2.3790.3161", dir:"\system32", bulletin:bulletin, kb:dnsapi_kb) ||
  (is_dns_svr && hotfix_is_vulnerable(os:"5.2", sp:1, file:"dns.exe", version:"5.2.3790.3161", dir:"\system32", bulletin:bulletin, kb:dnsexe_kb)) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"dnsapi.dll", version:"5.1.2600.3394", dir:"\system32", bulletin:bulletin, kb:dnsapi_kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"dnsapi.dll", version:"5.1.2600.5625", dir:"\system32", bulletin:bulletin, kb:dnsapi_kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"dnsapi.dll", version:"5.0.2195.7280", dir:"\system32", bulletin:bulletin, kb:dnsapi_kb) ||
  (is_dns_svr && hotfix_is_vulnerable(os:"5.0", file:"dns.exe", version:"5.0.2195.7162", dir:"\system32", bulletin:bulletin, kb:dnsexe_kb))
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
