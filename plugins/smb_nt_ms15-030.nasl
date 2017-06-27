#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(81744);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/02/23 22:37:42 $");

  script_cve_id("CVE-2015-0079");
  script_bugtraq_id(72921);
  script_osvdb_id(119385);
  script_xref(name:"MSFT", value:"MS15-030");

  script_name(english:"MS15-030: Vulnerability in Remote Desktop Protocol Could Allow Denial of Service (3039976)");
  script_summary(english:"Checks the version of Rdpudd.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a vulnerability due to a
failure by the Remote Desktop Protocol (RDP) to properly free objects
in memory. A remote, unauthenticated attacker, by creating multiple
RDP sessions, can exploit this to exhaust the system memory and cause
a denial of service.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-030");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 7, 8, 2012, 8.1,
and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/10");

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

bulletin = 'MS15-030';

kbs = make_list("3035017", "3036493");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
# Windows 2008 R2 is not affected, but Windows 7 is
if ("Server 2008 R2" >< productname || "Small Business Server 2011" >< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"rdpudd.dll", version:"6.3.9600.17667", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3035017") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpudd.dll", version:"6.2.9200.21364", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3035017") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"rdpudd.dll", version:"6.2.9200.17247", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3035017") ||

  # Windows 7
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpudd.dll", version:"6.1.7601.22947", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:"3035017") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpudd.dll", version:"6.1.7601.18740", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3035017") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpudd.dll", version:"6.2.9200.21364", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3036493") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"rdpudd.dll", version:"6.2.9200.17247", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3036493")
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
