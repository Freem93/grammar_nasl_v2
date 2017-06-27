#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58335);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/10/13 15:19:33 $");

  script_cve_id("CVE-2011-1388", "CVE-2011-1391", "CVE-2011-1392", "CVE-2012-0189");
  script_bugtraq_id(51448, 51184);
  script_osvdb_id(77994, 78568);

  script_name(english:"MS 2647518: Update Rollup for ActiveX Kill Bits (2647518)");
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

http://support.microsoft.com/kb/2647518"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

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
  '{ee5e14b0-4abf-409e-9c39-74f3d35bd85a}',# HP Photo Creative
  '{b34b19f4-7ebe-46cb-807c-746e72ebb4b6}',# HP Photo Creative
  '{7a7b986c-31e9-4286-88ca-b9dc481ca989}',# HP Photo Creative
  '{8290cb76-9f61-458b-ad2c-3f6fd2e8cd7d}',# HP Photo Creative
  '{dd7b057d-9020-4630-baf8-7a0cda04588d}',# HP Photo Creative
  '{fc7F9cc6-e049-4698-8a25-59ad87c7dce2}',# HP Photo Creative
  '{4ba9089c-ddfc-4206-b937-74484b06d305}',# Blueberry Software Flashback Component
  '{A3CD4BF9-EC17-47A4-833C-50A324D6FF35}',# Blueberry Software Flashback Component
  '{57733FF6-E100-4A4B-A7D1-A85AD17ABC54}',# Blueberry Software Flashback Component
  '{9B8E377B-7291-491A-B611-BB3E1D5F99F0}',# Blueberry Software Flashback Component
  '{6e84d662-9599-11d2-9367-20cc03c10627}',# Biostat SamplePower
  '{7e00a3b0-8f5c-11d2-baa4-04f205c10000}' # Biostat SamplePower 
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
