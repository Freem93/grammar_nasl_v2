#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35824);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2015/05/07 12:06:03 $");

  script_cve_id(
    "CVE-2009-0093",
    "CVE-2009-0094",
    "CVE-2009-0233",
    "CVE-2009-0234"
  );
  script_bugtraq_id(33982, 33988, 33989, 34013);
  script_osvdb_id(52517, 52518, 52519, 52520);
  script_xref(name:"IAVA", value:"2009-A-0018");
  script_xref(name:"MSFT", value:"MS09-008");
  script_xref(name:"CERT", value:"319331");

  script_name(english:"MS09-008: Vulnerabilities in DNS and WINS Server Could Allow Spoofing (962238)");
  script_summary(english:"Determines the presence of update 962238");

  script_set_attribute(attribute:"synopsis", value:"The remote host is vulnerable to DNS and/or WINS spoofing attacks.");
  script_set_attribute(attribute:"description", value:
"The remote host has a Windows DNS server and/or a Windows WINS server
installed.

Multiple vulnerabilities in the way that Windows DNS servers cache and
validate queries as well as the way that Windows DNS servers and Windows
WINS servers handle WPAD and ISATAP registration may allow remote
attackers to redirect network traffic intended for systems on the
Internet to the attacker's own systems.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms09-008");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, 2003 and
2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS09-008';
kbs = make_list("961063", "961064");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', win2003:'1,2', vista:'1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (!get_kb_item("SMB/Registry/HKLM/SYSTEM/CurrentControlSet/Services/DNS/DisplayName")) exit(0, "The host is not operate as a DNS server.");

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Vista" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2008
  #
  # nb: CVE-2009-0094 (WPAD WINS Server Registration Vulnerability) doesn't apply to 2008.
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Dns.exe", version:"6.0.6001.22375", min_version:"6.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:"961063") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Dns.exe", version:"6.0.6001.18214", dir:"\system32", bulletin:bulletin, kb:"961063") ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Dns.exe", version:"5.2.3790.4460", dir:"\System32", bulletin:bulletin, kb:"961063") ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Wins.exe", version:"5.2.3790.4446", dir:"\System32", bulletin:bulletin, kb:"961064") ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Dns.exe", version:"5.2.3790.3295", dir:"\System32", bulletin:bulletin, kb:"961063") ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Wins.exe", version:"5.2.3790.3281", dir:"\System32", bulletin:bulletin, kb:"961064") ||

  # Windows 2000
  hotfix_is_vulnerable(os:"5.0", file:"Dns.exe", version:"5.0.2195.7260", dir:"\System32", bulletin:bulletin, kb:"961063") ||
  hotfix_is_vulnerable(os:"5.0", file:"Wins.exe", version:"5.0.2195.7241", dir:"\System32", bulletin:bulletin, kb:"961064")
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
