#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(84743);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_cve_id("CVE-2015-2373");
  script_osvdb_id(124583);
  script_xref(name:"MSFT", value:"MS15-067");

  script_name(english:"MS15-067: Vulnerability in RDP Could Allow Remote Code Execution (3073094)");
  script_summary(english:"Checks the version of rdpcorets.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability due to improper handling of packets by the Remote
Desktop Protocol (RDP) service. A remote attacker can exploit this,
by sending a specially crafted sequence of packets to the remote RDP
server, to execute  arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-067");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/07/14");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-067';

kbs = make_list("3073094", "3069762");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
# Windows 2008 R2 is not affected, but Windows 7 is
if ("Server 2008 R2" >< productname || "Small Business Server 2011" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpcorets.dll", version:"6.2.9200.21506", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3067904") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpcorets.dll", version:"6.2.9200.17395", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3067904") ||

  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.1.7601.23095", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3067904") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.1.7601.18892", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3067904") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.2.9200.21506", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3069762") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpcorets.dll", version:"6.2.9200.17395", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3069762")
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
