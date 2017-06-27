#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57946);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2010-5082");
  script_bugtraq_id(44157);
  script_osvdb_id(68918);
  script_xref(name:"MSFT", value:"MS12-012");
  script_xref(name:"IAVB", value:"2012-B-0020");

  script_name(english:"MS12-012: Vulnerability in Color Control Panel Could Allow Remote Code Execution (2643719)");
  script_summary(english:"Checks the file version of Colorui.dll.");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote Windows host through
Windows Color Control Panel.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a version of Windows Color Control Panel
that is affected by an insecure library loading vulnerability.

A remote attacker could exploit this by tricking a user into opening a
.camp, .cdmp, .gmmp, .icc, or .icm file in a directory that also
contains a malicious 'sti.dll' file, resulting in arbitrary code
execution.");

  script_set_attribute(attribute:"see_also", value:"http://shinnai.altervista.org/exploits/SH-006-20100914.html");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-012");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2008, and 2008
R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/09/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS12-012';
kb = '2643719';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (
  "Windows Vista" >< productname ||
  "Windows 7" >< productname ||
  "Windows Embedded" >< productname
) exit(0, "The host is running "+productname+" and hence is not affected.");
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Colorui.dll", version:"6.1.7601.21879", min_version:"6.1.7601.21000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Colorui.dll", version:"6.1.7601.17745", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Colorui.dll", version:"6.1.7600.21109", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:0, file:"Colorui.dll", version:"6.1.7600.16931", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Colorui.dll", version:"6.0.6002.22757", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Colorui.dll", version:"6.0.6002.18552", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb)
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
