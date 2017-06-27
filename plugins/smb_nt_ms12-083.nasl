#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63230);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2012-2549");
  script_bugtraq_id(56840);
  script_osvdb_id(88311);
  script_xref(name:"MSFT", value:"MS12-083");
  script_xref(name:"IAVB", value:"2012-B-0122");

  script_name(english:"MS12-083: Vulnerability in IP-HTTPS Component Could Allow Security Feature Bypass (2765809)");
  script_summary(english:"Checks version of iphlpsvc.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is affected by a security feature bypass
vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A security feature bypass vulnerability exists in Windows due to the
way the IP-HTTPS Component handles certificates.  The vulnerability
could allow security feature bypass if an attacker presents a revoked
certificate to an IP-HTTPS server commonly used in Microsoft
DirectAccess deployments.  To exploit the vulnerability, the attacker
must use a certificate issued from the domain for IP-HTTPS server
authentication.

Successful exploitation of this vulnerability could allow the attacker
to bypass certificate validation checks.  Logging on to a system inside
the organization would still require system or domain credentials."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-083");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 2008 R2 and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS12-083';
kb = '2765809';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win7:'0,1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 7" >< productname || "Windows 8" >< productname || "Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"iphlpsvc.dll", version:"6.2.9200.16449", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"iphlpsvc.dll", version:"6.2.9200.20553", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"iphlpsvc.dll", version:"6.1.7600.17157", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"iphlpsvc.dll", version:"6.1.7600.21360", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"iphlpsvc.dll", version:"6.1.7601.17989", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"iphlpsvc.dll", version:"6.1.7601.22150", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb)
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
