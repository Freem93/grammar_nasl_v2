#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33134);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id("CVE-2007-0675", "CVE-2008-0956");
 script_bugtraq_id(29558);
 script_osvdb_id(33627, 46062, 46076, 46087);
 script_xref(name:"CERT", value:"216153");
 script_xref(name:"MSFT", value:"MS08-032");

 script_name(english:"MS08-032: Cumulative Security Update of ActiveX Kill Bits (950760)");
 script_summary(english:"Determines if sapi.dll kill bit is set");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple memory corruption vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host contains the sapi.dll ActiveX control.

The version of this control installed on the remote host reportedly
contains multiple memory corruption flaws.  If an attacker can trick a
user on the affected host into visiting a specially crafted web page, he
may be able to leverage this issue to execute arbitrary code on the host
subject to the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-032");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94, 119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/30");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/06/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS08-032';
kb = '950760';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

if (activex_init() != ACX_OK) exit(1, "activex_init() failed.");


# Test each control.
info = "";
clsids = make_list(
  "{47206204-5eca-11d2-960f-00c04f8ee628}",
  "{3bee4890-4fe9-4a37-8c1e-5e7e12791c1f}",
  "{40F23EB7-B397-4285-8F3C-AACE4FA40309}"
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
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    hotfix_security_warning();
  }
  else
  {
    set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
    hotfix_add_report(bulletin:bulletin, kb:kb);
    hotfix_security_warning();
  }
}
else audit(AUDIT_HOST_NOT, 'affected');
