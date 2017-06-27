#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(88649);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2016-0036");
  script_bugtraq_id(82799);
  script_osvdb_id(134321);
  script_xref(name:"MSFT", value:"MS16-017");
  script_xref(name:"IAVA", value:"2016-A-0048");

  script_name(english:"MS16-017: Security Update for Remote Desktop Display Driver to Address Elevation of Privilege (3134700)");
  script_summary(english:"Checks the version of rdpcorets.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the Remote Desktop Protocol (RDP) due to improper
handling of objects in memory. An authenticated, remote attacker can
exploit this by logging on via RDP and sending specially crafted data
over the authenticated connection, resulting in an elevation of
privilege.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-017");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 2012, 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
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

bulletin = 'MS16-017';

kbs = make_list("3126446", "3135174");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win7:"1", win8:"0", win81:"0", win10:"0") <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Windows 2008 R2 is not affected, 8.0 is dead.
if ("Server 2008 R2" >< productname || "Small Business Server 2011" >< productname ||
    ("Windows 8" >< productname && "8.1" >!< productname)
  )
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);

if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"rdpudd.dll", version:"10.0.10240.16683", min_version:"10.0.10240.15000", dir:"\system32", bulletin:bulletin, kb:"3135174") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"rdpudd.dll", version:"6.3.9600.18167", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3126446") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpudd.dll", version:"6.2.9200.21729", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3126446") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpudd.dll", version:"6.2.9200.17610", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3126446") ||

  # Windows 7  3126446
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpudd.dll", version:"6.2.9200.21729", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3126446") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpudd.dll", version:"6.2.9200.17610", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3126446")
)
{
  set_kb_item(name:'SMB/Missing/' + bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
