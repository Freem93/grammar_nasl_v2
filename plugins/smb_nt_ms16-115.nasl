#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(93474);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2016-3370", "CVE-2016-3374");
  script_bugtraq_id(92838, 92839);
  script_osvdb_id(144156, 144157);
  script_xref(name:"MSFT", value:"MS16-115");
  script_xref(name:"IAVA", value:"2016-A-0244");

  script_name(english:"MS16-115: Security Update for Microsoft Windows PDF Library (3188733)");
  script_summary(english:"Checks the version of glcndfilter.dll and windows.data.pdf.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple information disclosure vulnerabilities
in the Windows PDF Library due to improper handling of objects in
memory. An unauthenticated, remote attacker can exploit this
vulnerability, by convincing a user to open a specially crafted PDF
file or visit a website containing specially crafted PDF content, to
disclose sensitive information from memory.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-115");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, RT 8.1,
2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:L/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/09/13");

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

bulletin = 'MS16-115';
kbs = make_list('3184943', '3185611', '3185614', '3189866');

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Server Core 2012 R2 is not affected.
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"windows.data.pdf.dll", version:"6.3.9600.18454", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3184943")  ||
  # Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"glcndfilter.dll", version:"6.3.9600.18454", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3184943")  ||
  # Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"glcndfilter.dll", version:"6.2.9200.21954", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3184943") ||
  # Windows 10 1607
  hotfix_is_vulnerable(os:"10", sp:0, file:"windows.data.pdf.dll", version:"10.0.14393.187", os_build:"14393", dir:"\system32", bulletin:bulletin, kb:"3189866") ||
  # Windows 10 1511
  hotfix_is_vulnerable(os:"10", sp:0, file:"windows.data.pdf.dll", version:"10.0.10586.589", os_build:"10586", dir:"\system32", bulletin:bulletin, kb:"3185614") ||
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"windows.data.pdf.dll", version:"10.0.10240.17113", os_build:"10240", dir:"\system32", bulletin:bulletin, kb:"3185611")
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
