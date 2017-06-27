#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79311);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/04/19 13:27:09 $");

  script_cve_id("CVE-2014-6324");
  script_bugtraq_id(70958);
  script_osvdb_id(114751);
  script_xref(name:"CERT", value:"213119");
  script_xref(name:"IAVA", value:"2014-A-0180");
  script_xref(name:"MSFT", value:"MS14-068");

  script_name(english:"MS14-068: Vulnerability in Kerberos Could Allow Elevation of Privilege (3011780) (ESKIMOROLL)");
  script_summary(english:"Checks the version of kerberos.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote implementation of Kerberos KDC is affected by a privilege
escalation vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a privilege escalation
vulnerability due to the Kerberos Key Distribution Center (KDC)
implementation not properly validating signatures. A remote attacker
can exploit this vulnerability to elevate an unprivileged domain user
account to a domain administrator account.

ESKIMOROLL is one of multiple Equation Group vulnerabilities and
exploits disclosed on 2017/04/14 by a group known as the Shadow
Brokers.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-068");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/18");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS14-068';
kb = '3011780';
kbs = make_list(kb);

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
# Some of the 2k3 checks could flag XP 64, which is unsupported
if ("Windows XP" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"kerberos.dll", version:"6.3.9600.17423", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"kerberos.dll", version:"6.2.9200.21289", min_version:"6.2.9200.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"kerberos.dll", version:"6.2.9200.17172", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"kerberos.dll", version:"6.1.7601.22865", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"kerberos.dll", version:"6.1.7601.18658", min_version:"6.1.7601.17000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"kerberos.dll", version:"6.0.6002.23527", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"kerberos.dll", version:"6.0.6002.19220", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"kerberos.dll", version:"5.2.3790.5467", dir:"\system32", bulletin:bulletin, kb:kb)

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
