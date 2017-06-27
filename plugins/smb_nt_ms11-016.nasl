#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(52584);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/01/28 22:37:17 $");

  script_cve_id("CVE-2010-3146");
  script_bugtraq_id(42695);
  script_osvdb_id(67484);
  script_xref(name:"EDB-ID", value:"14746");
  script_xref(name:"IAVB", value:"2011-B-0034");
  script_xref(name:"MSFT", value:"MS11-016");

  script_name(english:"MS11-016: Vulnerability in Microsoft Groove Could Allow Remote Code Execution (2494047)");
  script_summary(english:"Checks version of Groove 2007");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through Microsoft
Office."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host contains a version of Microsoft Groove 2007
that incorrectly restricts the path used for loading external
libraries.

If an attacker can trick a user on the affected system into opening a
specially crafted Groove-related file located in the same network
directory as a specially crafted dynamic link library (DLL) file, he
may be able to leverage this issue to execute arbitrary code subject
to the user's privileges."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-016");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a patch for Groove 2007.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/08/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:groove");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_nt_ms02-031.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-016';
kbs = make_list("2494047");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


fix = '12.0.6550.5004';
vuln = 0;
installs = get_kb_list_or_exit("SMB/Office/Groove/*/ProductPath");
foreach install (keys(installs))
{
  version = install - 'SMB/Office/Groove/' - '/ProductPath';
  path = installs[install];
  if (isnull(path)) path = 'n/a';  # this shouldn't be null, but just in case

  if (
    version =~ '^12.' &&  # make sure it's groove 2007
    ver_compare(ver:version, fix:fix) == -1
  )
  {
    vuln++;
    info =
      '\n  Product           : Groove 2007' +
      '\n  File              : ' + path +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : ' + fix + '\n';
    hotfix_add_report(bulletin:"MS11-016", kb:"2494047", info);
  }
}
if (vuln)
{
  set_kb_item(name:'SMB/Missing/MS11-016', value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
