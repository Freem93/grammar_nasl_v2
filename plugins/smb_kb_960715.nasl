#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35634);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
  "CVE-2008-4252",
  "CVE-2008-4253",
  "CVE-2008-4254",
  "CVE-2008-4255",
  "CVE-2008-4256",
  "CVE-2009-0305"
 );
 script_bugtraq_id(33663);
 script_osvdb_id(50577, 50578, 50579, 50580, 50581, 51833);
 script_xref(name:"IAVA", value:"2008-A-0088");
 script_xref(name:"IAVA", value:"2009-A-0016");
 script_xref(name:"IAVB", value:"2009-B-0009");

 script_name(english:"MS KB960715: Cumulative Security Update of ActiveX Kill Bits");
 script_summary(english:"Determines if the newest kill bits are set");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update containing
ActiveX kill bits.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing a list of kill bits for ActiveX controls
that are known to contain vulnerabilities. 

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues.");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released an advisory about this :

http://technet.microsoft.com/en-us/security/advisory/960715");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
 script_cwe_id(119, 189, 264, 399);

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/11");
 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
  "{FFBB3F3B-0A5A-4106-BE53-DFE1E2340CB1}",
  "{4788DE08-3552-49EA-AC8C-233DA52523B9}",
  "{1E216240-1B7D-11CF-9D53-00AA003C9CB6}",
  "{3A2B370C-BA0A-11d1-B137-0000F8753F5D}",
  "{B09DE715-87C1-11d1-8BE3-0000F8754DA1}",
  "{cde57a43-8b86-11d0-b3c6-00a0c90aea82}",
  "{6262d3a0-531b-11cf-91f6-c2863c385e30}",
  "{0ECD9B64-23AA-11d0-B351-00A0C9055D8E}",
  "{C932BA85-4374-101B-A56C-00AA003668DC}",
  "{248dd896-bb45-11cf-9abc-0080c7e7b78d}"
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
