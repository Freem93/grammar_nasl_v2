#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57033);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/02/12 16:01:11 $");

  script_name(english:"Microsoft Patch Bulletin Feasibility Check");
  script_summary(english:"Determine if it's possible to test for Microsoft patches locally or through a third-party tool.");

  script_set_attribute(attribute:'synopsis', value:"Nessus is able to check for Microsoft patch bulletins.");
  script_set_attribute(attribute:'description', value:
"Using credentials supplied in the scan policy, Nessus is able to
collect information about the software and patches installed on the
remote Windows host and will use that information to check for missing
Microsoft security updates.

Note that this plugin is purely informational.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/06");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "sccm_get_missing_updates.nbin", "wsus_get_missing_updates.nbin", "os_fingerprint.nasl");
  if (defined_func("xmlparse")) script_dependencies("shavlik_missing_patches.nbin", "ibm_tem_get_missing_updates.nbin");
  if (NASL_LEVEL >= 5200) script_dependencies("dell_kace_k1000_get_missing_updates.nbin", "symantec_altiris_get_missing_updates.nbin");
  script_require_ports(139, 445, "patch_management/ran");

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");

smb_report = '\n\nNessus is able to test for missing patches using : \n';
credentialed_checks = FALSE;

if (
  !isnull(get_kb_item("SMB/Registry/Enumerated")) &&
  is_accessible_share()
)
{
  credentialed_checks = TRUE;
  smb_report += '  Nessus\n';
}

if (!isnull(get_kb_item('patch_management/ran')))
{
  credentialed_checks = TRUE;
  set_kb_item(name:"SMB/MS_Bulletin_Checks/Possible", value:TRUE);
  set_kb_item(name:"Host/patch_management_checks", value:TRUE);

  foreach tool (keys(_pmtool_names))
  {
    if (get_kb_item("patch_management/"+tool))
    {
      tool_name = _pmtool_names[tool];
      smb_report += "  " + tool_name + '\n';
    }
  }
}
if (credentialed_checks)
{
  set_kb_item(name:"SMB/MS_Bulletin_Checks/Possible", value:TRUE);
  if (defined_func('report_xml_tag')) 
    report_xml_tag(tag:"Credentialed_Scan", value:"true");
}

if (!isnull(get_kb_item("SMB/MS_Bulletin_Checks/Possible")))
{
  port = get_kb_item("SMB/transport");
  if (report_verbosity > 0) security_note(port:port, extra:smb_report);
  else security_note(port);
}
else
{
  os = get_kb_item("Host/OS");
  if (!isnull(os) && "indows" >< os) exit(0, "Nessus is not able to test for Microsoft's patch bulletins.");
  else exit(0, "The host does not appear to be running Windows.");
}
