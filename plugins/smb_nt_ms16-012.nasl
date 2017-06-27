#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88644);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/29 19:33:20 $");

  script_cve_id("CVE-2016-0046", "CVE-2016-0058");
  script_bugtraq_id(82636, 82638);
  script_osvdb_id(134306, 134307);
  script_xref(name:"MSFT", value:"MS16-012");

  script_name(english:"MS16-012: Security Update for Microsoft Windows PDF Library to Address Remote Code Execution (3138938)");
  script_summary(english:"Checks the version of glcndfilter.dll and windows.data.pdf.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple code execution vulnerabilities :

  - A remote code execution vulnerability exists in Windows
    Reader. An attacker can exploit this, by convincing a
    user to open a specially crafted file, to execute
    arbitrary code in the context of the current user.
    (CVE-2016-0046)

  - A flaw exists in the Microsoft Windows PDF Library due
    to improper handling of API calls. An attacker can
    exploit this, by convincing a user to open a specially
    crafted file, to execute arbitrary code in the context
    of the current user. (CVE-2016-0058).");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-012");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2012, 8.1, 2012
R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS16-012';
kbs = make_list('3123294', '3135174');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win8:'0', win81:'0', win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# Server Core 2012 R2 is listed as affected, however no update
# is offered and the files in question do not exist in a close look
# at a 2012 R2 core host.
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share))
  audit(AUDIT_SHARE_FAIL, share);

if (
  # 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"glcndfilter.dll", version:"6.2.9200.21761", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3123294") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"glcndfilter.dll", version:"6.2.9200.17642", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3123294") ||
  # 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"glcndfilter.dll", version:"6.3.9600.18184", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3123294")  ||
  # 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"windows.data.pdf.dll", version:"10.0.10240.16683", dir:"\system32", bulletin:bulletin, kb:"3135174")
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
