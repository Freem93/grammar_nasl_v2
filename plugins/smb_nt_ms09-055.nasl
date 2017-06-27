#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(42111);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2016/05/06 17:11:38 $");

  script_cve_id("CVE-2009-2493");
  script_bugtraq_id(35828);
  script_osvdb_id(56698);
  script_xref(name:"MSFT", value:"MS09-055");
  script_xref(name:"CERT", value:"456745");

  script_name(english:"MS09-055: Cumulative Security Update of ActiveX Kill Bits (973525)");
  script_summary(english:"Checks if several kill bits have been set");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has multiple ActiveX controls that are affected
by multiple code execution vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"Microsoft ActiveX controls that were compiled using the vulnerable
Active Template Library described in Microsoft Security Bulletin
MS09-035 have remote code execution vulnerabilities.  A remote attacker
could exploit them to execute arbitrary code by tricking a user into
requesting a maliciously crafted web page.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS09-055");
  script_set_attribute( attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(264);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/07/28");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS09-055';
kb = '973525';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Test each control.
info = "";
clsids = make_list(
  "{0002E531-0000-0000-C000-000000000046}",  # msowc.dll
  "{4C85388F-1500-11D1-A0DF-00C04FC9E20F}",  # msowc.dll
  "{0002E532-0000-0000-C000-000000000046}",  # msowc.dll
  "{0002E554-0000-0000-C000-000000000046}",  # owc10.dll
  "{0002E55C-0000-0000-C000-000000000046}",  # owc11.dll
  "{279D6C9A-652E-4833-BEFC-312CA8887857}",  # viewer.dll
  "{B1F78FEF-3DB7-4C56-AF2B-5DCCC7C42331}",  # msmail.dll
  "{C832BE8F-4B89-4579-A217-DB92E7A27915}",  # msmail.dll
  "{A9A7297E-969C-43F1-A1EF-51EBEA36F850}",  # mailcomm.dll
  "{DD8C2179-1B4A-4951-B432-5DE3D1507142}",  # msmail.dll
  "{4F1E5B1A-2A80-42ca-8532-2D05CB959537}",  # MsnPUpld.dll
  "{27A3D328-D206-4106-8D33-1AA39B13394B}",  # ReportBuilderAddin.dll
  "{DB640C86-731C-484A-AAAF-750656C9187D}",  # ReportBuilderAddin.dll
  "{15721a53-8448-4731-8bfc-ed11e128e444}",  # ReportBuilderAddin.dll
  "{3267123E-530D-4E73-9DA7-79F01D86A89F}"   # ReportBuilderAddin.dll
);

foreach clsid (clsids)
{
  # Make sure the control is installed
  file = activex_get_filename(clsid:clsid);
  if (isnull(file) || !file) continue;

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

    report = string(
      "\n",
      "The kill bit has not been set for the following control", s, " :\n",
      "\n",
      info
    );

    if (!thorough_tests)
    {
      report = string(
        report,
        "\n",
        "Note that Nessus did not check whether there were other kill bits\n",
        "that have not been set because the 'Perofrm thorough tests' setting\n",
        "was not enabled when this scan was run.\n"
      );
    }
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    security_warning(port:kb_smb_transport(), extra:report);
  }
  else
  {
   hotfix_add_report(bulletin:bulletin, kb:kb);
   hotfix_security_warning();
  }

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
}
else audit(AUDIT_HOST_NOT, 'affected');
