#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34414);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");

 script_name(english:"MS KB956391: Cumulative Security Update of ActiveX Kill Bits");
 script_summary(english:"Determines if the newest kill bits are set");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update containing
ActiveX kill bits");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a list of kill bits for ActiveX controls
that are known to contain vulnerabilities. 

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues.");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released an advisory about this :

http://technet.microsoft.com/en-us/security/advisory/956391");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/15");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 
 script_dependencies("smb_hotfixes.nasl");
 script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
 script_require_ports(139, 445);
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:2) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");


# Test each control.
info = "";
clsids = make_list(
  "{AED98630-0251-4E83-917D-43A23D66D507}",
  "{67A5F8DC-1A4B-4D66-9F24-A704AD929EEE}",
  "{E48BB416-C578-4A62-84C9-5E3389ABE5FC}",
  "{0002E500-0000-0000-C000-000000000046}",
  "{0002E520-0000-0000-C000-000000000046}",
  # "{0002E510-0000-0000-C000-000000000046}",
  "{0002E511-0000-0000-C000-000000000046}",
  "{0002E530-0000-0000-C000-000000000046}",
  "{F0E42D50-368C-11D0-AD81-00A0C90DC8D9}",
  "{F0E42D60-368C-11D0-AD81-00A0C90DC8D9}",
  "{F2175210-368C-11D0-AD81-00A0C90DC8D9}",
  "{FA91DF8D-53AB-455D-AB20-F2F023E498D3}"
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
    security_warning(port:kb_smb_transport(), extra:report);
  }
  else security_warning(kb_smb_transport());
}
