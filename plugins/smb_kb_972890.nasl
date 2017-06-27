#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39622);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id("CVE-2008-0015");
  script_bugtraq_id(35558);
  script_osvdb_id(55651);
  script_xref(name:"MSFT", value:"MS09-032");

  script_name(english:"MS09-032: Cumulative Security Update of ActiveX Kill Bits (973346)");
  script_summary(english:"Checks kill bits for each affected control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update containing
ActiveX kill bits.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing a list of kill bits for ActiveX controls
that are known to contain vulnerabilities.

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/MS09-032");
  script_set_attribute(  attribute:"solution",  value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft DirectShow (msvidctl.dll) MPEG-2 Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/07/07");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-032';
kb = '973346';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);


if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");


# Test each control.
info = "";
clsids = make_list(
  "{011B3619-FE63-4814-8A84-15A194CE9CE3}",
  "{0149EEDF-D08F-4142-8D73-D23903D21E90}",
  "{0369B4E5-45B6-11D3-B650-00C04F79498E}",
  "{0369B4E6-45B6-11D3-B650-00C04F79498E}",
  "{055CB2D7-2969-45CD-914B-76890722F112}",
  "{0955AC62-BF2E-4CBA-A2B9-A63F772D46CF}",
  "{15D6504A-5494-499C-886C-973C9E53B9F1}",
  "{1BE49F30-0E1B-11D3-9D8E-00C04F72D980}",
  "{1C15D484-911D-11D2-B632-00C04F79498E}",
  "{1DF7D126-4050-47F0-A7CF-4C4CA9241333}",
  "{2C63E4EB-4CEA-41B8-919C-E947EA19A77C}",
  "{334125C0-77E5-11D3-B653-00C04F79498E}",
  "{37B0353C-A4C8-11D2-B634-00C04F79498E}",
  "{37B03543-A4C8-11D2-B634-00C04F79498E}",
  "{37B03544-A4C8-11D2-B634-00C04F79498E}",
  "{418008F3-CF67-4668-9628-10DC52BE1D08}",
  "{4A5869CF-929D-4040-AE03-FCAFC5B9CD42}",
  "{577FAA18-4518-445E-8F70-1473F8CF4BA4}",
  "{59DC47A8-116C-11D3-9D8E-00C04F72D980}",
  "{7F9CB14D-48E4-43B6-9346-1AEBC39C64D3}",
  "{823535A0-0318-11D3-9D8E-00C04F72D980}",
  "{8872FF1B-98FA-4D7A-8D93-C9F1055F85BB}",
  "{8A674B4C-1F63-11D3-B64C-00C04F79498E}",
  "{8A674B4D-1F63-11D3-B64C-00C04F79498E}",
  "{9CD64701-BDF3-4D14-8E03-F12983D86664}",
  "{9E77AAC4-35E5-42A1-BDC2-8F3FF399847C}",
  "{A1A2B1C4-0E3A-11D3-9D8E-00C04F72D980}",
  "{A2E3074E-6C3D-11D3-B653-00C04F79498E}",
  "{A2E30750-6C3D-11D3-B653-00C04F79498E}",
  "{A8DCF3D5-0780-4EF4-8A83-2CFFAACB8ACE}",
  "{AD8E510D-217F-409B-8076-29C5E73B98E8}",
  "{B0EDF163-910A-11D2-B632-00C04F79498E}",
  "{B64016F3-C9A2-4066-96F0-BD9563314726}",
  "{BB530C63-D9DF-4B49-9439-63453962E598}",
  "{C531D9FD-9685-4028-8B68-6E1232079F1E}",
  "{C5702CCC-9B79-11D3-B654-00C04F79498E}",
  "{C5702CCD-9B79-11D3-B654-00C04F79498E}",
  "{C5702CCE-9B79-11D3-B654-00C04F79498E}",
  "{C5702CCF-9B79-11D3-B654-00C04F79498E}",
  "{C5702CD0-9B79-11D3-B654-00C04F79498E}",
  "{C6B14B32-76AA-4A86-A7AC-5C79AAF58DA7}",
  "{CAAFDD83-CEFC-4E3D-BA03-175F17A24F91}",
  "{D02AAC50-027E-11D3-9D8E-00C04F72D980}",
  "{F9769A06-7ACA-4E39-9CFB-97BB35F0E77E}",
  "{FA7C375B-66A7-4280-879D-FD459C84BB02}"
);

foreach clsid (clsids)
{
  if (activex_get_killbit(clsid:clsid) == 0)
  {
    info += '  ' + clsid + '\n';
    if (!thorough_tests) break;
  }
}
activex_end();


if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report =
      '\nThe kill bit has not been set for the following control'+s+' :\n\n'+
      info;

    if (!thorough_tests)
    {
      report +=
        '\nNote that Nessus did not check whether there were other kill bits\n'+
        'that have not been set because the "Perform thorough tests" setting\n'+
        'was not enabled when this scan was run.\n';
    }
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
  }
  else hotfix_add_report(bulletin:bulletin, kb:kb);

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
}
else audit(AUDIT_HOST_NOT, 'affected');
