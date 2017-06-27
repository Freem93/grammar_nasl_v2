#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84746);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2015-2387");
  #script_bugtraq_id();
  script_osvdb_id(124197);
  script_xref(name:"MSFT", value:"MS15-077");

  script_name(english:"MS15-077: Vulnerability in ATM Font Driver Could Allow Elevation of Privilege (3077657)");
  script_summary(english:"Checks the file version of atmfd.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The Adobe Font driver on the remote host is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability in the Adobe Type Manager Font Driver (ATMFD) due to a
failure to properly handle objects in memory. A local attacker can
exploit this by running a specially crafted application, resulting in
arbitrary code execution with elevated privileges.");
  script_set_attribute(attribute:"see_also", value:"https://twitter.com/hackerfantastic/status/618104999785156608");
  # http://blog.trendmicro.com/trendlabs-security-intelligence/a-look-at-the-open-type-font-manager-vulnerability-from-the-hacking-team-leak/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?928cb8c6");
  script_set_attribute(attribute:"see_also", value:"https://code.google.com/p/google-security-research/issues/detail?id=473");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-077");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, RT, 2012, 8.1, RT 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/06"); # date of tweet referenced above
  script_set_attribute(attribute:"patch_publication_date", value:"2015/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/07/14");

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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-077';
kb = '3077657';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);
if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# Some of the 2k3 checks could flag XP 64, which is unsupported
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"atmfd.dll", version:"5.1.2.242", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"atmfd.dll", version:"5.1.2.242", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"atmfd.dll", version:"5.1.2.242", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"atmfd.dll", version:"5.1.2.242", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"atmfd.dll", version:"5.2.2.242", dir:"\system32", bulletin:bulletin, kb:kb)
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
