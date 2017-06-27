#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(66867);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2013-1331");
  script_bugtraq_id(60408);
  script_osvdb_id(94127);
  script_xref(name:"MSFT", value:"MS13-051");

  script_name(english:"MS13-051: Vulnerability in Microsoft Office Could Allow Remote Code Execution (2839571)");
  script_summary(english:"Checks version of mso.dll");

  script_set_attribute(attribute:"synopsis", value:"The remote Office install has a buffer overflow vulnerability.");
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has a version of Microsoft Office that contains
a buffer overflow vulnerability that arises because certain Microsoft
Office components for processing PNG files do not properly handle memory
allocation.

If an attacker can trick a user on the affected host into opening a
specially crafted Office file, this issue could be leveraged to execute
arbitrary code subject to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-051");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Office 2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office:2003");

  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS13-051';
kb = '2817421';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

# Ensure Office is installed
office_vers = hotfix_check_office_version();
if (isnull(office_vers)) audit(AUDIT_NOT_INST, "Microsoft Office");

# Ensure we can get common files directory
commonfiles = hotfix_get_officecommonfilesdir(officever:"11.0");
if (!commonfiles) exit(1, "Error getting Office Common Files directory.");

# Ensure share is accessible
share = ereg_replace(pattern:"^([A-Za-z]):.*", replace:"\1$", string:commonfiles);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = FALSE;
# Office 2003 SP3
if (office_vers["11.0"])
{
  office_sp = get_kb_item("SMB/Office/2003/SP");
  if (!isnull(office_sp) && office_sp == 3)
  {

    path = commonfiles + "\Microsoft Shared\Office11";

    if (
      hotfix_is_vulnerable(file:"Mso.dll", version:"11.0.8403", min_version:'11.0.0.0', path:path, bulletin:bulletin, kb:kb)
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
