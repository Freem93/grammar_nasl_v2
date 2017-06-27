#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35069);
 script_version("$Revision: 1.36 $");
 script_cvs_date("$Date: 2016/12/09 20:55:00 $");

 script_cve_id(
  "CVE-2008-3704",
  "CVE-2008-4252",
  "CVE-2008-4253",
  "CVE-2008-4254",
  "CVE-2008-4255",
  "CVE-2008-4256"
 );
 script_bugtraq_id(30674, 32591, 32592, 32612, 32613, 32614);
 script_osvdb_id(47475, 50577, 50578, 50579, 50580, 50581);
 script_xref(name:"IAVA", value:"2008-A-0088");
 script_xref(name:"MSFT", value:"MS08-070");

 script_name(english:"MS08-070: Vulnerabilities in Visual Basic 6.0 ActiveX Controls Could Allow Remote Code Execution (932349)");
 script_summary(english:"Determines the presence of update 932349");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the ActiveX control for Visual
Basic 6.0 Runtime Extended Files that may allow an attacker to execute
arbitrary code on the remote host by constructing a malicious web page
and enticing a victim to visit it.

Note that this control may have been included with Visual Studio or
FoxPro or as part of a third-party application created by one of those
products.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-070");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Microsoft Office /
Frontpage / FoxPro / Studio.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'Microsoft Visual Studio Mdmask32.ocx ActiveX Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_cwe_id(119, 189, 264, 399);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_basic");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_studio_.net");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_foxpro");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:visual_frontpage");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:project");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("smb_func.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_activex_func.inc");


include("misc_func.inc");
get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-070';
kbs = make_list("932349");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

if (activex_init() != ACX_OK) exit(1, "Could not initialize the ActiveX checks");

info = "";

vers = make_array();

clsids = make_list(
  "{1E216240-1B7D-11CF-9D53-00AA003C9CB6}", # Comct232.ocx
  "{3A2B370C-BA0A-11d1-B137-0000F8753F5D}", # Mschrt20.ocx
  "{B09DE715-87C1-11d1-8BE3-0000F8754DA1}", # Mscomct2.ocx
  "{cde57a43-8b86-11d0-b3c6-00a0c90aea82}", # Msdatgrd.ocx
  "{6262d3a0-531b-11cf-91f6-c2863c385e30}", # Msflxgrd.ocx
  "{0ECD9B64-23AA-11d0-B351-00A0C9055D8E}", # Mshflxgd.ocx
  "{C932BA85-4374-101B-A56C-00AA003668DC}", # Msmask32.ocx
  "{248dd896-bb45-11cf-9abc-0080c7e7b78d}"  # Mswinsck.ocx
 );

foreach clsid (clsids)
{
  file = activex_get_filename(clsid:clsid);

  if(file)
  {
    file = tolower(file);
    if ("msflxgrd.ocx" >< file) fix = "6.1.98.6";
    else if ("mscomct2.ocx" >< file) fix = "6.1.98.11";
    else if ("comct232.ocx" >< file) fix = "6.0.98.12";
    else fix = "6.1.98.12";

    if(isnull(vers[clsid]))
      vers[clsid] = activex_get_fileversion(clsid:clsid);

    if (vers[clsid] && activex_check_fileversion(clsid:clsid, fix:fix) == TRUE )
    {
      if (report_paranoia > 1 || activex_get_killbit(clsid:clsid) == 0 )
      {
        info += string(
            "\n",
            "  Class Identifier   : ", clsid, "\n",
            "  Filename           : ", file, "\n",
            "  Installed version  : ", vers[clsid], "\n",
            "  Fix                : ",fix,"\n"
          );

        if (!thorough_tests) break;
      }
    }
  }
}
activex_end();


kb       = '932349';

if (info != "")
{
  set_kb_item(name:"SMB/Missing/MS08-070", value:TRUE);

  if (report_paranoia > 1)
  {
    report = string(
      "\n",
      "Nessus found the following affected control(s) installed :\n",
      "\n",
      info,
      "\n",
      "Note that Nessus did not check whether the kill bit was set for\n",
      "the control(s) because of the Report Paranoia setting in effect\n",
      "when this scan was run.\n"
      );
  }
  else
  {
    report = string(
      "\n",
      "Nessus found the following affected control(s) installed :\n",
      "\n",
      info,
      "\n",
      "Moreover, the kill bit was not set for the control(s) so they\n",
      "are accessible via Internet Explorer.\n"
      );
  }
  hotfix_add_report(report, bulletin:bulletin, kb:kb);
  hotfix_security_hole();
}
else exit(0, "The host is not affected.");
