#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(33878);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2008-1457", "CVE-2008-1456");
 script_bugtraq_id(30584, 30586);
 script_osvdb_id(47411, 47412);
 script_xref(name:"MSFT", value:"MS08-049");
 script_xref(name:"IAVT", value:"2008-T-0039");

 script_name(english:"MS08-049: Vulnerabilities in Event System Could Allow Remote Code Execution (950974)");
 script_summary(english:"Determines the presence of update 950974");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the
Microsoft Event System.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a vulnerability in the Event
System that might allow an attacker to execute arbitrary code on the
remote host.

To exploit this vulnerability, an attacker with valid login
credentials would need to send a malformed subscription request to the
remote Event System.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-049");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/08/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/13");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"I");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
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
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-049';
kb = '950974';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"es.dll", version:"2001.12.6930.16677", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"es.dll", version:"2001.12.6930.20818", min_version:"2001.12.6930.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"es.dll", version:"2001.12.6931.18057", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"es.dll", version:"2001.12.6931.22162", min_version:"2001.12.6931.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"es.dll", version:"2001.12.4720.4282", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"es.dll", version:"2001.12.4720.3129", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:3, file:"es.dll", version:"2001.12.4414.706", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"es.dll", version:"2001.12.4414.320", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"es.dll", version:"2000.2.3550.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
