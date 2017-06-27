#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(44418);
  script_version("$Revision: 1.28 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2009-2570", "CVE-2009-3735", "CVE-2010-0252");
  script_bugtraq_id(34766, 38045, 38060, 38066, 38067);
  script_osvdb_id(54137, 62246, 62267, 62372, 62438);
  script_xref(name:"MSFT", value:"MS10-008");

  script_name(english:"MS10-008: Cumulative Security Update of ActiveX Kill Bits (978262)");
  script_summary(english:"Checks if several kill bits have been set");

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
requesting a maliciously crafted web page, resulting in arbitrary code
execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-008");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, and 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(94, 119);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/04/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, 'Host/patch_management_checks');

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_activex_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-008';
kbs = make_list("978262");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "The registry wasn't enumerated.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3, win7:1) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");



kb = "978262";

# Test each control.
info = "";
clsids = make_list(
  '{E0ECA9C3-D669-4EF4-8231-00724ED9288F}', # max3activex.dll
  '{C05A1FBC-1413-11D1-B05F-00805F4945F6}', # Symantec WinFax Pro 10.3
  '{5D80A6D1-B500-47DA-82B8-EB9875F85B4D}', # Google Desktop Gadget 5.8
  '{0CCA191D-13A6-4E29-B746-314DEE697D83}', # Facebook Photo Updater 5.5.8
  '{2d8ed06d-3c30-438b-96ae-4d110fdc1fb8}'  # PandaActiveScan Installer 2.0
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
    hotfix_add_report(info, bulletin:bulletin, kb:kb);
  }
  hotfix_security_warning();

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
}
else exit(0, "The host is not affected.");
