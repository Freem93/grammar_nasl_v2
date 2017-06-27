#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25166);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/05/19 18:02:18 $");

 script_cve_id(
  "CVE-2007-0323",
  "CVE-2007-0942",
  "CVE-2007-0944",
  "CVE-2007-0945",
  "CVE-2007-0946",
  "CVE-2007-0947",
  "CVE-2007-2221"
 );
 script_bugtraq_id(23331, 23769, 23770, 23771, 23772, 23827);
 script_osvdb_id(34399, 34400, 34401, 34402, 34403, 34404, 35873);
 script_xref(name:"MSFT", value:"MS07-027");
 script_xref(name:"CERT", value:"500753");
 script_xref(name:"CERT", value:"869641");
 script_xref(name:"EDB-ID", value:"3892");

 script_name(english:"MS07-027: Cumulative Security Update for Internet Explorer (931768)");
 script_summary(english:"Determines the presence of update 931768");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing the IE cumulative security update 931768.

The remote version of IE is vulnerable to several flaws that could allow
an attacker to execute arbitrary code on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-027");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/05/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}


include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_activex_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-027';
kb = '931768';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);


rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);


vuln = 0;


if (activex_init() != ACX_OK) exit(1, "Could not initialize the ActiveX checks.");

# Check for controls for which the kill bit was set.
#
# nb: we'll collect info about missing kill bits now but report
#     them later, if Mshtml.dll appears to have been patched.
info = "";

clsids = make_list(
  "{1D95A7C7-3282-4DB7-9A48-7C39CE152A19}",
  "{D9998BD0-7957-11D2-8FED-00606730D3AA}"
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


# Check for patched Mshtml.dll.
if (
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2885", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Mshtml.dll", version:"6.0.3790.4026", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.16441", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", file:"Mshtml.dll", version:"7.0.6000.20544", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2800.1593", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"7.0.6000.16441", min_version:"7.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"6.0.2800.1593", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.0", file:"Mshtml.dll", version:"5.0.3850.1900", dir:"\system32", bulletin:bulletin, kb:kb)
) vuln++;


# Report if any of the kill bits are unset.
if (info)
{
  vuln++;
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);

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
    hotfix_add_report(report, bulletin:bulletin, kb:kb);
  }
  else hotfix_add_report(bulletin:bulletin, kb:kb);
}


if (vuln)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
