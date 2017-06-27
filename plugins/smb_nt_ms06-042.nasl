#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22184);
 script_version("$Revision: 1.46 $");
 script_cvs_date("$Date: 2016/12/09 20:54:59 $");

 script_cve_id(
  "CVE-2004-1166",
  "CVE-2006-3280",
  "CVE-2006-3450",
  "CVE-2006-3451",
  "CVE-2006-3637",
  "CVE-2006-3638",
  "CVE-2006-3639",
  "CVE-2006-3640",
  "CVE-2006-3873",
  "CVE-2006-7066"
 );
 script_bugtraq_id(
  11826,
  18277,
  18682,
  19228,
  19312,
  19316,
  19339,
  19340,
  19400,
  19987
 );
 script_osvdb_id(
  12299,
  26956,
  27533,
  27850,
  27851,
  27852,
  27853,
  27854,
  27855,
  30834
 );
 script_xref(name:"CERT", value:"883108");
 script_xref(name:"CERT", value:"252764");
 script_xref(name:"CERT", value:"340060");
 script_xref(name:"CERT", value:"262004");
 script_xref(name:"CERT", value:"119180");
 script_xref(name:"MSFT", value:"MS06-042");

 script_name(english:"MS06-042: Cumulative Security Update for Internet Explorer (918899)");
 script_summary(english:"Determines the presence of update 918899");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is missing IE Cumulative Security Update 918899.

The remote version of IE is vulnerable to several flaws that could
allow an attacker to execute arbitrary code on the remote host.

Note that Microsoft has re-released this hotfix since the initial
version contained a buffer overflow.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-042");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(94);
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/kb/923762/");

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/06");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/08/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-042';
kb = '918899';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Urlmon.dll", version:"6.0.3790.566", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.2", sp:1, file:"Mshtml.dll", version:"6.0.3790.2759", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:1, file:"Urlmon.dll", version:"6.0.2800.1572", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", sp:2, file:"Mshtml.dll", version:"6.0.2900.2963", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Urlmon.dll", version:"6.0.2800.1572", min_version:"6.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.0", file:"Urlmon.dll", version:"5.0.3844.3000", dir:"\system32", bulletin:bulletin, kb:kb) )
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
