#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88648);

  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2016-0051");
  script_bugtraq_id(82682);
  script_osvdb_id(134320);
  script_xref(name:"MSFT", value:"MS16-016");
  script_xref(name:"IAVA", value:"2016-A-0049");

  script_name(english:"MS16-016: Security Update for WebDAV to Address Elevation of Privilege (3136041)");
  script_summary(english:"Checks the version of mrxdav.sys");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a flaw in the Microsoft Web Distributed
Authoring and Versioning (WebDAV) client due to improper validation of
user-supplied input. A local attacker can exploit this, via a
specially crafted application, to execute arbitrary code with elevated
privileges.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-016");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS16-016 mrxdav.sys WebDav Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS16-016';
kbs = make_list('3135173', '3124280', '3135174');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Windows 8" >< productname && "8.1" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mrxdav.sys", version:"6.3.9600.18189", min_version:"6.3.9600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280") ||

  # Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mrxdav.sys", version:"6.2.9200.21738", min_version:"6.2.9200.20000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mrxdav.sys", version:"6.2.9200.17619", min_version:"6.2.9200.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mrxdav.sys", version:"6.1.7601.23317", min_version:"6.1.7601.22000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mrxdav.sys", version:"6.1.7601.19113", min_version:"6.1.7600.16000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mrxdav.sys", version:"6.0.6002.23886", min_version:"6.0.6002.23000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mrxdav.sys", version:"6.0.6002.19576", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:"3124280")
)
  vuln++;
if (
  # 10 RTM
  hotfix_is_vulnerable(os:"10", sp:0, file:"mrxdav.sys", version:"10.0.10240.16683", dir:"\system32\drivers", bulletin:bulletin, kb:"3135174") ||
  # 10 threshold 2 (aka 1511)
  hotfix_is_vulnerable(os:"10", sp:0, file:"mrxdav.sys", version:"10.0.10586.103", min_version:"10.0.10586.0", dir:"\system32\drivers", bulletin:bulletin, kb:"3135173")
)
  vuln++;

if (vuln)
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

