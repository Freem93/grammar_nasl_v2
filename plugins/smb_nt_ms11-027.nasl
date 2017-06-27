#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53384);
  script_version("$Revision: 1.26 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0811", "CVE-2010-2193", "CVE-2010-3973", "CVE-2011-1205", "CVE-2011-1243");
  script_bugtraq_id(40490, 40689, 45546, 47091, 47197);
  script_osvdb_id(65218, 65381, 65382, 69942, 71788, 73775);
  script_xref(name:"CERT", value:"725596");
  script_xref(name:"MSFT", value:"MS11-027");

  script_name(english:"MS11-027: Cumulative Security Update of ActiveX Kill Bits (2508272)");
  script_summary(english:"Checks if kill bits have been set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is missing an update that disables selected
ActiveX controls."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host has one or more ActiveX controls installed that
could be abused to execute arbitrary code remotely if a user can be
tricked into viewing a malicious web page using Internet Explorer.

Three of these controls are from Microsoft itself while the others are
from third-party vendors that have asked Microsoft to prevent their
controls from being run in Internet Explorer."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-027");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Microsoft WMI Administration Tools ActiveX Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'White_Phosphorus');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS11-027';
kb = '2508272';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

# Test each control.
info = "";
clsids = make_list(
  '{1A6FE369-F28C-4AD9-A3E6-2BCB50807CF1}',  # Microsoft Internet Explorer 8 Developer Tools
  '{29851043-AA76-4efd-9232-4914DD0AD4A1}',  # IBM Rational Suite License ActiveX Control
  '{2745E5F5-D234-11D0-847A-00C04FD7BB08}',  # Microsoft WMITools ActiveX
  '{2C37C480-CEE3-11D1-82C3-0060089253D0}',  # IBM Rational Suite License ActiveX Control
  '{4918D1BD-B497-4f2f-A429-3C3CD74694FE}',  # IBM Rational Suite License ActiveX Control
  '{4F496A52-13F7-483d-B5E2-0FC4AA567749}',  # IBM Rational Suite License ActiveX Control
  '{53655704-5956-11D3-91AA-005004B34F28}',  # IBM Rational Suite License ActiveX Control
  '{687F154E-1099-11D4-91F9-005004B34F28}',  # IBM Rational Suite License ActiveX Control
  '{6F225D94-9318-11D4-9223-005004B34F28}',  # IBM Rational Suite License ActiveX Control
  '{7B297BFD-85E4-4092-B2AF-16A91B2EA103}',  # CA WebScan ActiveX
  '{83F0C8F0-4900-4909-A0AD-A5BAAC432739}',  # IBM Rational Suite License ActiveX Control
  '{8469A9DE-A3BF-4218-A1D2-F19AA9EA1617}',  # IBM Rational Suite License ActiveX Control
  '{AC146530-87A5-11D1-ADBD-00AA00B8E05A}',  # Microsoft WMITools ActiveX
  '{B3F90F4F-B521-4c76-BE28-DB569320CB8F}',  # IBM Rational Suite License ActiveX Control
  '{C679DECC-5289-4856-B504-74B11ADD424A}',  # IBM Rational Suite License ActiveX Control
  '{CAFEEFAC-DEC7-0000-0000-ABCDEFFEDCBA}',  # Oracle Java Deployment Toolkit
  '{FA44198C-E0B3-4f10-8B77-F646EC7CE684}',  # IBM Rational Suite License ActiveX Control
  '{FB7199AB-79BF-11d2-8D94-0000F875C541}',  # Microsoft Windows Messenger ActiveX
  '{FF371BF4-213D-11D0-95F3-00C04FD9B15B}'   # Microsoft WMITools ActiveX
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
  hotfix_security_warning();
}
else audit(AUDIT_HOST_NOT, 'affected');
