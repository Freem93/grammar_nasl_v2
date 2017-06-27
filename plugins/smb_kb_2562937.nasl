#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(55802);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/06 17:11:37 $");

  script_cve_id("CVE-2011-0331", "CVE-2011-1207", "CVE-2011-1827");
  script_bugtraq_id(46930, 47643, 47695);
  script_osvdb_id(71249, 72136, 74807);
  script_xref(name:"ICS-ALERT", value:"11-103-01A");

  script_name(english:"MS 2562937: Update Rollup for ActiveX Kill Bits (2562937)");
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
"The remote Windows host is missing a list of kill bits for ActiveX
controls that are known to contain vulnerabilities. 

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues.

Note that the affected controls are from third-party vendors that have
asked Microsoft to prevent their controls from being run in Internet
Explorer."
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2 :

http://support.microsoft.com/kb/2562937"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:TF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/31");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp(xp:4, win2003:3, vista:3, win7:2) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");


# Test each control.
info = "";
clsids = make_list(
  '{B4CB50E4-0309-4906-86EA-10B6641C8392}',  # CheckPoint SSL VPN On-Demand
  '{E4F874A0-56ED-11D0-9C43-00A0C90F29FC}',  # ActBar
  '{FB7FE605-A832-11D1-88A8-0000E8D220A6}'   # EBI R Web Toolkit
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

  hotfix_security_warning();
}
else exit(0, "The host is not affected.");
