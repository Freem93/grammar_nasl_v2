#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59044);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_cve_id("CVE-2012-0358");
  script_bugtraq_id(52482);
  script_osvdb_id(80042);
  script_xref(name:"CERT", value:"339177");

  script_name(english:"MS 2695962: Update Rollup for ActiveX Kill Bits (2695962)");
  script_summary(english:"Checks if kill bit has been set");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote Windows host is missing an update that disables a selected
ActiveX control."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote Windows host is missing a kill bit for an ActiveX
control that is known to contain vulnerabilities.

If this ActiveX control is ever installed on the remote host,
either now or in the future, it would expose the host to various
security issues.

Note that the affected control is from a third-party vendor that has
asked Microsoft to prevent their control from being run in Internet
Explorer."
  );
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/2695962");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
2008, 7, and 2008 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

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
  '{B8E73359-3422-4384-8D27-4EA1B4C01232}' # Cisco Clientless VPN
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
else exit(0, "The host is not affected.");
