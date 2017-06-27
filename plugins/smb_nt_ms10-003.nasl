#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44413);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0243");
  script_bugtraq_id(38073);
  script_osvdb_id(62235);
  script_xref(name:"MSFT", value:"MS10-003");

  script_name(english:"MS10-003: Vulnerability in Microsoft Office (MSO.DLL) Could Allow Remote Code Execution (978214)");
  script_summary(english:"Checks version of mso.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Office.");
  script_set_attribute(attribute:"description", value:
"The remote host contains a vulnerable version of Microsoft Office XP.
Opening a specially crafted Office file can result in a buffer
overflow. A remote attacker could exploit this by tricking a user into
opening a malicious Office file.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-003");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office XP.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119);
  script_set_attribute(attribute:"see_also", value:"http://www.coresecurity.com/content/excel-buffer-overflow");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS10-003';
kb = "977896";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

arch = get_kb_item_or_exit("SMB/ARCH");
if (!is_accessible_share()) exit(1, "is_accessible_share() failed.");

office_versions = hotfix_check_office_version();
office_sp = get_kb_item_or_exit("SMB/Office/XP/SP");

x86_path = hotfix_get_commonfilesdir() + "\Microsoft Shared\Office10";
if (!x86_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');
x64_path = hotfix_get_programfilesdirx86() + "\Common Files\Microsoft Shared\Office10";
if (arch == 'x64' && !x64_path) audit(AUDIT_PATH_NOT_DETERMINED, 'Program Files (x86)');

if (
  (office_versions["10.0"] && office_sp == 3) &&
  (
    hotfix_is_vulnerable(file:"Mso.dll", version:"10.0.6858.0", path:x86_path, bulletin:bulletin, kb:kb) ||
    hotfix_is_vulnerable(file:"Mso.dll", arch:"x64", version:"10.0.6858.0", path:x64_path, bulletin:bulletin, kb:kb)
  )
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
