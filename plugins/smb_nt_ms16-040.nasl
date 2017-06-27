#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90434);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/03/21 13:39:52 $");

  script_cve_id("CVE-2016-0147");
  script_bugtraq_id(85909);
  script_osvdb_id(136966);
  script_xref(name:"MSFT", value:"MS16-040");
  script_xref(name:"IAVA", value:"2016-A-0092");

  script_name(english:"MS16-040: Security Update for Microsoft XML Core Services (3148541)");
  script_summary(english:"Checks the file version of Msxml3.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability in the Microsoft XML Core Services (MSXML) parser due to
improper validation of user-supplied input. An unauthenticated, remote
attacker can exploit this vulnerability, by convincing a user to visit
a specially-crafted website that is designed to invoke MSXML through
Internet Explorer, to execute arbitrary code in the context of the
current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-040");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS16-040';
kbs = make_list("3146963", "3147458", "3147461");

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0',  win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"Msxml3.dll", version:"8.110.10586.212", min_version:"8.110.10586.0", dir:"\system32", bulletin:bulletin, kb:"3147458") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"Msxml3.dll", version:"8.110.10240.16766", min_version:"8.110.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3147461") ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Msxml3.dll", version:"8.110.9600.18258", min_version:"8.110.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3146963") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Msxml3.dll", version:"8.110.9200.21793", min_version:"8.110.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3146963") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Msxml3.dll", version:"8.110.7601.23373", min_version:"8.110.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3146963") ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Msxml3.dll", version:"8.100.5013.0", dir:"\system32", bulletin:bulletin, kb:"3146963")
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
