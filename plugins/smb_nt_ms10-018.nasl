#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(45378);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/12/09 21:04:53 $");

  script_cve_id("CVE-2010-0267", "CVE-2010-0488", "CVE-2010-0489", "CVE-2010-0490", "CVE-2010-0491",
                "CVE-2010-0492", "CVE-2010-0494", "CVE-2010-0805", "CVE-2010-0806", "CVE-2010-0807");
  script_bugtraq_id(38615, 39023, 39024, 39025, 39026, 39027, 39028, 39030, 39031, 39047);
  script_osvdb_id(
    62810,
    63327,
    63328,
    63329,
    63330,
    63331,
    63332,
    63333,
    63334,
    63335
  );
  script_xref(name:"CERT", value:"744549");
  script_xref(name:"MSFT", value:"MS10-018");

  script_name(english:"MS10-018: Cumulative Security Update for Internet Explorer (980182)");
  script_summary(english:"Checks version of Mshtml.dll / MSrating.dll");

  script_set_attribute(
    attribute:"synopsis",
    value:
"Arbitrary code can be executed on the remote host through a web
browser."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote host is missing IE Security Update 980182.

The remote version of IE is affected by several vulnerabilities that
may allow an attacker to execute arbitrary code on the remote host."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-018");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista, 2008, and Windows 7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS10-018 Microsoft Internet Explorer DHTML Behaviors Use After Free');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/03/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/30");

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

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS10-018';
kbs = make_list("980182");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'2', vista:'0,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "980182";

if (
  # Windows 7 and Windows Server 2008 R2
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1",                   file:"Mshtml.dll", version:"8.0.7600.20651", min_version:"8.0.7600.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1",                   file:"Mshtml.dll", version:"8.0.7600.16535", min_version:"8.0.7600.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0",                   file:"Mshtml.dll", version:"8.0.6001.22995", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0",                   file:"Mshtml.dll", version:"8.0.6001.18904", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mshtml.dll", version:"7.0.6002.22360", min_version:"7.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2,             file:"Mshtml.dll", version:"7.0.6002.18226", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mshtml.dll", version:"7.0.6001.22653", min_version:"7.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1,             file:"Mshtml.dll", version:"7.0.6001.18444", min_version:"7.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Mshtml.dll", version:"7.0.6000.21242", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0,             file:"Mshtml.dll", version:"7.0.6000.17037", min_version:"7.0.6000.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2003 / XP x64
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mshtml.dll", version:"8.0.6001.22995", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mshtml.dll", version:"8.0.6001.18904", min_version:"8.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mshtml.dll", version:"7.0.6000.21228", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mshtml.dll", version:"7.0.6000.17023", min_version:"7.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
   # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.2", sp:2,             file:"Mshtml.dll", version:"6.0.3790.4672",  min_version:"6.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  #
  # - Internet Explorer 8
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22995", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18904", min_version:"8.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.22995", min_version:"8.0.6001.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"8.0.6001.18904", min_version:"8.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 7
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.21228", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.17023", min_version:"7.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.21228", min_version:"7.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"7.0.6000.17023", min_version:"7.0.0.0",        dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6 SP1
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Msrating.dll", version:"6.0.2900.3676",  min_version:"6.0.0.0",      dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 6
  hotfix_is_vulnerable(os:"5.1", sp:3, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.5945",  min_version:"6.0.2900.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, arch:"x86", file:"Mshtml.dll", version:"6.0.2900.3676",  min_version:"6.0.2900.0",     dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 2000
  #
  # - Internet Explorer 6 w/ Service Pack 1
  hotfix_is_vulnerable(os:"5.0",                   file:"Msrating.dll", version:"6.0.2800.2002", min_version:"6.0.0.0",       dir:"\system32", bulletin:bulletin, kb:kb) ||
  # - Internet Explorer 5.01 w/ Service Pack 4
  hotfix_is_vulnerable(os:"5.0",                   file:"Mshtml.dll",   version:"5.0.3886.1900", min_version:"5.0.0.0",       dir:"\system32", bulletin:bulletin, kb:kb)
)
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
