#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31796);
 script_version("$Revision: 1.28 $");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");

 script_cve_id("CVE-2008-1086");
 script_bugtraq_id(28606);
 script_osvdb_id(44171);
 script_xref(name:"MSFT", value:"MS08-023");

 script_name(english:"MS08-023: Security Update of ActiveX Kill Bits (948881)");
 script_summary(english:"Determines if hxvz.dll kill bit is set");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has an ActiveX control that is affected by
multiple buffer overflow vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host contains the hxvz.dll ActiveX control.

The version of this control installed on the remote host reportedly
contains multiple stack-based buffer overflows.  If an attacker can
trick a user on the affected host into visiting a specially crafted
web page, this issue could be leveraged to execute arbitrary code on
the host subject to the user's privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-023");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/04/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/04/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

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

bulletin = 'MS08-023';
kbs = make_list("948881");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);


if (!get_kb_item("SMB/Registry/Enumerated")) exit(1, "The registry wasn't enumerated.");

# Locate the file used by the controls.
if (activex_init() != ACX_OK) exit(1, "Unable to initialize the ActiveX API.");

info = "";
clsids = make_list(
"{314111b8-a502-11d2-bbca-00c04f8ec294}",
"{314111c6-a502-11d2-bbca-00c04f8ec294}"
);

foreach clsid (clsids)
{
  if (activex_is_installed(clsid:clsid) == TRUE &&
      activex_get_killbit(clsid:clsid) == 0
  )
  {
    info += '  ' +clsid + '\n';
    if (!thorough_tests) break;
  }
}
activex_end();


kb       = '948881';

if (info)
{
  if (report_verbosity > 0)
  {
    if (max_index(split(info)) > 1) s = "s";
    else s = "";

    report =
      '\n' +
      'The kill bit has not been set for the following control'+s+' :\n\n'+
      info;

    if (!thorough_tests)
    {
      report +=
        '\n' +
        'Note that Nessus did not check whether there were other kill bits\n'+
        'that have not been set because the "Perform thorough tests" setting\n'+
        'was not enabled when this scan was run.\n';
    }
    set_kb_item(name:"SMB/Missing/MS08-023", value:TRUE);
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
    hotfix_security_warning();
  }
  else
  {
    set_kb_item(name:"SMB/Missing/MS08-023", value:TRUE);
    hotfix_add_report(bulletin:bulletin, kb:kb);
    hotfix_security_warning();
  }
}
else exit(0, "The host is not affected.");
