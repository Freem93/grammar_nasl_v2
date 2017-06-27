#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58329);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/12/12 18:38:05 $");

  script_cve_id("CVE-2012-0006");
  script_bugtraq_id(52374);
  script_osvdb_id(80005);
  script_xref(name:"MSFT", value:"MS12-017");

  script_name(english:"MS12-017: Vulnerability in DNS Server Could Allow Denial of Service (2647170)");
  script_summary(english:"Checks file version of Dns.exe");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote Windows host is susceptible to a denial of service attack."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The DNS server installed on the remote host does not properly handle
objects in memory when looking up the resource record of a domain. By
sending a specially crafted DNS query, an attacker may be able to
exploit this flaw and cause the DNS server on the remote host to stop
responding and eventually restart."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-017");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2003, 2008, and
2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-017';
kb = '2647170';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("XP" >< productname || "Windows Vista" >< productname || "Windows 7" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
path = get_registry_value(handle:hklm, item:"SYSTEM\CurrentControlSet\Services\DNS\ImagePath");
RegCloseKey(handle:hklm);
close_registry();

if (isnull(path))
  exit(0, 'The DNS role is not enabled on the remote host.');

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2008 R2 and Windows Server 2008 R2 SP1
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dns.exe", version:"6.1.7601.21885", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Dns.exe", version:"6.1.7601.17750", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Dns.exe", version:"6.1.7600.21114", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Dns.exe", version:"6.1.7600.16936", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2008 SP2 x86/x64
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dns.exe", version:"6.0.6002.22763", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Dns.exe", version:"6.0.6002.18557", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 SP2 x64/x86
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Dns.exe", version:"5.2.3790.4957",  dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
