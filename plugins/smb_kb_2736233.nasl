#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62045);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/09/06 13:39:48 $");

  script_cve_id(
    "CVE-2012-2493",
    "CVE-2012-2494",
    "CVE-2012-2495",
    "CVE-2012-2496"
  );
  script_bugtraq_id(54107, 54108);
  script_osvdb_id(83096, 83159);

  script_name(english:"MS 2736233: Update Rollup for ActiveX Kill Bits (2736233)");
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
"The remote Windows host is missing one or more kill bits for ActiveX
controls that are known to contain vulnerabilities. 

If any of these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose the host to various
security issues. 

Note that the affected controls are from a third-party vendor that has
asked Microsoft to prevent their controls from being run in Internet
Explorer."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2 :

http://technet.microsoft.com/en-us/security/advisory/2736233"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");

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

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'2', win7:'0,1') <= 0) 
  audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE); 
if ("Windows Embedded" >< productname) exit(0, "The host is running "+productname+" and hence is not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

# Test each control.
info = "";
clsids = make_list(
  # Cisco Secure Desktop 
  '{705ec6d4-b138-4079-a307-ef13e4889a82}',
  '{f8fc1530-0608-11df-2008-0800200c9a66}',
  '{e34f52fe-7769-46ce-8f8b-5e8abad2e9fc}',

  # Cisco Hostscan
  '{f8fc1530-0608-11df-2008-0800200c9a66}',
  '{e34f52fe-7769-46ce-8f8b-5e8abad2e9fc}',

  # Cisco AnyConnect Secure Mobility Client
  '{55963676-2f5e-4baf-ac28-cf26aa587566}',
  '{cc679cb8-dc4b-458b-b817-d447b3b6ac31}'
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
    hotfix_add_report(report);
  }
  else hotfix_add_report();

  hotfix_security_hole();
}
else audit(AUDIT_HOST_NOT, 'affected'); 
