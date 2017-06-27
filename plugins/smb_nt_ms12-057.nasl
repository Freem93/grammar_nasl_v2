#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(61532);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/07/01 20:31:47 $");

  script_cve_id("CVE-2012-2524");
  script_bugtraq_id(54876);
  script_osvdb_id(84605);
  script_xref(name:"MSFT", value:"MS12-057");
  script_xref(name:"IAVB", value:"2012-B-0075");

  script_name(english:"MS12-057: Vulnerabilities in Microsoft Office Could Allow Remote Code Execution (2731879)");
  script_summary(english:"Checks versions of mso.dll and msconv97.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of Microsoft Office that is
potentially affected by a remote code execution vulnerability.
Specially crafted Computer Graphics Metafile (CGM) graphics files can be
used to exploit this vulnerability and allow an attacker to take control
of an affected system."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms12-057");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Office 2007 and 2010.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/15");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");

  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "office_installed.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS12-057';
kbs = make_list("2553260", "2589322", "2596615", "2596754", "2687501", "2687510");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


office_vers = hotfix_check_office_version();
if (isnull(office_vers)) audit(AUDIT_NOT_INST, "Microsoft Office");

common = hotfix_get_commonfilesdir();
if (!common) exit(1, "hotfix_get_commonfilesdir() failed.");

share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:common);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = FALSE;
# Office 2010
if (office_vers["14.0"])
{
  office_sp = get_kb_item("SMB/Office/2010/SP");
  if (!isnull(office_sp) && office_sp == 1)
  {
    x86_path = common + "\Microsoft Shared\Office14";
    x64_path = hotfix_get_programfilesdirx86() + "\Common Files\Microsoft Shared\Office14";

    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"14.0.6123.5001", min_version:'14.0.0.0', path:x86_path, bulletin:bulletin, kb:"2687501") ||
      hotfix_is_vulnerable(file:"Mso.dll", version:"14.0.6123.5001", min_version:'14.0.0.0', path:x64_path, bulletin:bulletin, kb:"2687501") ||

      hotfix_is_vulnerable(file:"Msconv97.dll", version:"2010.1400.6123.5000", min_version:'2010.0.0.0', path:x86_path, bulletin:bulletin, kb:"2687510") ||
      hotfix_is_vulnerable(file:"Msconv97.dll", version:"2010.1400.6123.5000", min_version:'2010.0.0.0', path:x64_path, bulletin:bulletin, kb:"2687510")
    ) vuln = TRUE;
  }
}
# Office 2007
if (office_vers["12.0"])
{
  office_sp = get_kb_item("SMB/Office/2007/SP");
  if (!isnull(office_sp) && (office_sp == 2 || office_sp == 3))
  {
    x86_path = common + "\Microsoft Shared\Office12";
    x64_path = hotfix_get_programfilesdirx86() + "\Common Files\Microsoft Shared\Office12";

    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"12.0.6662.5000", min_version:'12.0.0.0', path:x86_path, bulletin:bulletin, kb:"2596615") ||
      hotfix_is_vulnerable(file:"Mso.dll", version:"12.0.6662.5000", min_version:'12.0.0.0', path:x64_path, bulletin:bulletin, kb:"2596615") ||

      hotfix_is_vulnerable(file:"Msconv97.dll", version:"2006.1200.6662.5000", min_version:'2006.0.0.0', path:x86_path, bulletin:bulletin, kb:"2596754") ||
      hotfix_is_vulnerable(file:"Msconv97.dll", version:"2006.1200.6662.5000", min_version:'2006.0.0.0', path:x64_path, bulletin:bulletin, kb:"2596754")
    ) vuln = TRUE;
  }
}

if (vuln)
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
