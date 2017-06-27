#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40891);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2008-4609", "CVE-2009-1925", "CVE-2009-1926");
  script_bugtraq_id(31545, 36265, 36269);
  script_osvdb_id(57795, 57796, 57797);
  script_xref(name:"MSFT", value:"MS09-048");
  script_xref(name:"IAVA", value:"2009-A-0077");

  script_name(english:"MS09-048: Vulnerabilities in Windows TCP/IP Could Allow Remote Code Execution (967723)");
  script_summary(english:"Checks version of tcpip.sys");

  script_set_attribute(attribute:"synopsis", value:
"Multiple vulnerabilities in the Windows TCP/IP implementation could
lead to denial of service or remote code execution.");
  script_set_attribute(attribute:"description", value:
"The TCP/IP implementation on the remote host has multiple flaws that
could allow remote code execution if an attacker sent specially crafted
TCP/IP packets over the network to a computer with a listening service :

  - A denial of service vulnerability exists in TCP/IP
    processing in Microsoft Windows due to the way that
    Windows handles an excessive number of established TCP
    connections. The affect of this vulnerability can be
    amplified by the requirement to process specially
    crafted packets with a TCP receive window size set to a
    very small value or zero. An attacker could exploit the
    vulnerability by flooding a system with specially
    crafted packets causing the affected system to stop
    responding to new requests or automatically restart.
    (CVE-2008-4609)

  - A remote code execution vulnerability exists in the
    Windows TCP/IP stack due to the TCP/IP stack not
    cleaning up state information correctly. This causes the
    TCP/IP stack to reference a field as a function pointer
    when it actually contains other information. An anonymous
    attacker could exploit the vulnerability by sending
    specially crafted TCP/IP packets to a computer that has
    a service listening over the network. An attacker who
    successfully exploited this vulnerability could take
    complete control of an affected system. (CVE-2009-1925)

  - A denial of service vulnerability exists in TCP/IP
    processing in Microsoft Windows due to an error in the
    processing of specially crafted packets with a small or
    zero TCP receive window size. If an application closes a
    TCP connection with pending data to be sent and an
    attacker has set a small or zero TCP receive window
    size, the affected server will not be able to
    completely close the TCP connection. An attacker could
    exploit the vulnerability by flooding a system with
    specially crafted packets causing the affected system
    to stop responding to new requests. The system would
    remain non-responsive even after the attacker stops
    sending malicious packets. (CVE-2009-1926)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-048");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista and
2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(16, 94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-048';
kb = '967723';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# nb: MS09-048 says that Windows 2000 and XP are affected but will not be patched.
if ("Windows 2000" >< productname || "Windows XP" >< productname) exit(0, productname+" is affected, but Microsoft is not making an update available for it.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"tcpip.sys", version:"6.0.6002.22200", min_version:"6.0.6002.20000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"tcpip.sys", version:"6.0.6002.18091",                               dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"tcpip.sys", version:"6.0.6001.22497", min_version:"6.0.6001.20000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"tcpip.sys", version:"6.0.6001.18311",                               dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"tcpip.sys", version:"6.0.6000.21108", min_version:"6.0.6000.20000", dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"tcpip.sys", version:"6.0.6000.16908",                               dir:"\System32\drivers", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"tcpip.sys", version:"5.2.3790.4573", dir:"\System32\drivers", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
