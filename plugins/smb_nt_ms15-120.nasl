#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86830);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/29 19:33:19 $");

  script_cve_id("CVE-2015-6111");
  script_bugtraq_id(77481);
  script_osvdb_id(130063);
  script_xref(name:"MSFT", value:"MS15-120");
  script_xref(name:"IAVB", value:"2015-B-0133");

  script_name(english:"MS15-120: Security Update for IPSec to Address Denial of Service (3102939)");
  script_summary(english:"Checks the version of ikeext.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a denial of service
vulnerability in the Internet Protocol Security (IPSec) service due to
improper handling of encryption negotiation. An authenticated, remote
attacker can exploit this, via a malicious application, to cause the
host to become unresponsive.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-120");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 8, 2012, 8.1, and
2012 R2");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

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

bulletin = 'MS15-120';
kbs = make_list('3102939');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"ikeext.dll", version:"6.3.9600.18086", dir:"\system32", bulletin:bulletin, kb:"3102939") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ikeext.dll", version:"6.2.9200.21656", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3102939") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"ikeext.dll", version:"6.2.9200.17539", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3102939")
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
