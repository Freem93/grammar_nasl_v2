#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(46841);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_cve_id("CVE-2010-0252", "CVE-2010-0811", "CVE-2010-2193");
  script_bugtraq_id(38045, 40490, 40494, 40496, 40535);
  script_osvdb_id(62246, 65218, 65382, 65468, 65480, 65481);
  script_xref(name:"MSFT", value:"MS10-034");

  script_name(english:"MS10-034: Cumulative Security Update of ActiveX Kill Bits (980195)");
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
"The Microsoft Data Analyzer ActiveX control has a remote code
execution vulnerability.  The system may also have one or more
vulnerable third-party ActiveX controls installed.

A remote attacker could exploit these issues by tricking a user into
requesting a maliciously crafted web page, resulting in arbitrary
code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-034");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(94);

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");
include("smb_hotfixes_fcheck.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-034';
kbs = make_list("980195");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The registry wasn't enumerated.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3, win7:1) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");


# Test each control.
info = "";

kb = '980195';
clsids = make_list(
  '{14FD1463-1F3F-4357-9C03-2080B442F503}',  # Office Excel ActiveX control for Data Analysis (max3activex.dll)
  '{E9CB13DB-20AB-43C5-B283-977C58FB5754}',  # Office Excel ActiveX control for Data Analysis (max3activex.dll)
  '{8fe85d00-4647-40b9-87e4-5eb8a52f4759}',  # Microsoft Internet Explorer 8 Developer Tools (iedvtool.dll)
  '{F6A56D95-A3A3-11D2-AC26-400000058481}',  # Danske eSec ActiveX
  '{56393399-041A-4650-94C7-13DFCB1F4665}',  # CA PSFormX ActiveX (Pest Scan)
  '{6f750200-1362-4815-a476-88533de61d0c}',  # Kodak Ofoto Upload Manager / Kodak Gallery Easy Upload Manager ActiveX Control
  '{6f750201-1362-4815-a476-88533de61d0c}',  # Kodak Ofoto Upload Manager / Kodak Gallery Easy Upload Manager ActiveX Control
  '{7F14A9EE-6989-11D5-8152-00C04F191FCA}'   # Avaya CallPilot Unified Messaging
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
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
}
else exit(0, "The host is not affected.");
