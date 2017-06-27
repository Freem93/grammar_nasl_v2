#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(59909);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/12/01 15:02:06 $");

  script_cve_id("CVE-2012-1854");
  script_bugtraq_id(54303);
  script_osvdb_id(83655);
  script_xref(name:"MSFT", value:"MS12-046");
  script_xref(name:"IAVA", value:"2012-A-0109");

  script_name(english:"MS12-046: Vulnerability in Visual Basic for Applications Could Allow Remote Code Execution (2707960)");
  script_summary(english:"Checks version of Vbe6.dll / Vbe7.dll / Vbajet32.Dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Visual Basic
for Applications."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of Visual Basic for Applications installed on the remote
host is affected by an insecure library loading vulnerability.

A remote attacker could exploit this flaw by tricking a user into
opening a legitimate Microsoft Office file located in the same
directory as a maliciously crafted dynamic link library (DLL) file,
resulting in arbitrary code execution.

Note that if an affected copy of VBE6.DLL was installed by a third-
party application, it may be necessary to contact that application's
vendor for an update."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/security/advisory/2269637");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-046");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Office as well as Visual
Basic for Applications Runtime and SDK."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic_software_development_kit");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");
include("audit.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS12-046';
kbs = make_list('2598361', '2596744', '2598243', '2553447', '2688865', '2687626');
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit('SMB/Registry/Enumerated');
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

common = hotfix_get_commonfilesdir();
if (!common) exit(1, "hotfix_get_commonfilesdir() failed.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

# Determine the applicable KB for the VBA6 related software
vba6_kb = '2688865';
office_ver = hotfix_check_office_version();
if (office_ver)
{
  # Office 2007
  if (office_ver['12.0']) vba6_kb = "2596744";
  # Office 2003
  else if (office_ver['11.0']) vba6_kb = "2598361";
}

vuln = 0;

# Office 2010
if (office_ver['14.0'])
{
  vuln += hotfix_is_vulnerable(path:common+"\Microsoft Shared\VBA\VBA7", file:"Vbe7.dll", version:"7.00.16.27", bulletin:bulletin, kb:"2598243");
  vuln += hotfix_is_vulnerable(path:common+"\Microsoft Shared\OFFICE14", file:"Vbajet32.Dll", version:"6.0.1.1627", bulletin:bulletin, kb:"2553447");
}

# Office 2003 / 2007 / VBA
vuln += hotfix_is_vulnerable(path:common+"\Microsoft Shared\VBA\VBA6", file:"Vbe6.dll", version:"6.5.10.54", bulletin:bulletin, kb:vba6_kb);

if (vuln > 0)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  exit(0, 'The host is not affected.');
}
