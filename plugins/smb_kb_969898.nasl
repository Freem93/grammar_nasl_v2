#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39350);
  script_version("$Revision: 1.24 $");
  script_cvs_date("$Date: 2016/12/09 20:54:59 $");

  script_cve_id("CVE-2008-0024", "CVE-2008-2475", "CVE-2009-0208");
  script_bugtraq_id(33918, 35218, 35247, 35248);
  script_osvdb_id(52830, 54968, 82563);

  script_name(english:"MS KB969898: Cumulative Security Update of ActiveX Kill Bits");
  script_summary(english:"Checks kill bits for each affected control");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is missing a security update containing
ActiveX kill bits.");
  script_set_attribute(attribute:"description", value:
"The remote host is missing a list of kill bits for ActiveX controls
that are known to contain vulnerabilities.

If these ActiveX controls are ever installed on the remote host,
either now or in the future, they would expose it to various security
issues.");
  script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/advisory/969898");
  script_set_attribute(attribute:"solution", value:"Microsoft has released an advisory about this.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(78, 94);

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/10");
  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
 
  script_dependencies("smb_hotfixes.nasl");
  script_require_keys("SMB/Registry/Enumerated", "SMB/WindowsVersion");
  script_require_ports(139, 445);

  exit(0);
}


include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


if (!get_kb_item("SMB/Registry/Enumerated")) exit(0, "The 'SMB/Registry/Enumerated' KB item is missing.");
if (hotfix_check_sp(win2k:6, xp:4, win2003:3, vista:3) <= 0)
  exit(0, "The host is not affected based on its version / service pack.");
if (hotfix_check_server_core() == 1) exit(0, "Windows Server Core installs are not affected.");
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");


# Test each control.
info = "";
clsids = make_list(
  # Microsoft Visual Studio 'MSCOMM32.OCX' ActiveX Control (CVE-2008-0024)
  "{648A5600-2C6E-101B-82B6-000000000014}",
  # Derivco ActiveX Control (BID 35247)
  "{D8089245-3211-40F6-819B-9E5E92CD61A2}",
  # eBay Enhanced Picture Service ActiveX Control (CVE-2008-2475)
  "{4C39376E-FA9D-4349-BACC-D305C1750EF3}",
  "{C3EB1670-84E0-4EDA-B570-0B51AAE81679}",
  # HP Virtual Rooms Client ActiveX Control (CVE-2009-0208)
  "{00000032-9593-4264-8B29-930B3E4EDCCD}"
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
