#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90441);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2017/04/24 13:38:11 $");

  script_cve_id("CVE-2016-0151");
  script_bugtraq_id(85913);
  script_osvdb_id(136977);
  script_xref(name:"MSFT", value:"MS16-048");
  script_xref(name:"IAVB", value:"2016-B-0065");

  script_name(english:"MS16-048: Security Update for CSRSS (3148528)");
  script_summary(english:"Checks the version of basesrv.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a security feature bypass vulnerability in the
Client-Server Run-time Subsystem (CSRSS) due to improper management of
process tokens in memory. A local attacker can exploit this
vulnerability, via a specially crafted application, to escalate
privileges and execute arbitrary code as an administrator.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-048");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS16-048';
kbs = make_list('3146723', '3147458', '3147461');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"basesrv.dll", version:"6.3.9600.18258", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3146723")  ||

  # Windows 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"basesrv.dll", version:"6.2.9200.21793", min_version:"6.2.9200.17000", dir:"\system32", bulletin:bulletin, kb:"3146723") ||

  # Windows 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"basesrv.dll", version:"10.0.10586.212", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3147458") ||

  # Windows 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"basesrv.dll", version:"10.0.10240.16766", dir:"\system32", bulletin:bulletin, kb:"3147461")
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
