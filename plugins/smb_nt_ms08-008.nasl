#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(31042);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/04/23 21:11:57 $");

 script_cve_id("CVE-2007-0065");
 script_bugtraq_id(27661);
 script_osvdb_id(41463);
 script_xref(name:"IAVA", value:"2008-A-0006");
 script_xref(name:"MSFT", value:"MS08-008");

 script_name(english:"MS08-008: Vulnerability in OLE Automation Could Allow Remote Code Execution (947890)");
 script_summary(english:"Determines the presence of update 947890");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of Microsoft Windows that has a
vulnerability in the OLE Automation component that can be abused by an
attacker to execute arbitrary code on the remote host.

An attacker may be able to execute arbitrary code on the remote host by
constructing a malicious script and enticing a victim to visit a web
site or view a specially crafted email message.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS08-008");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(94);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS08-008';
kb = '943055';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Oleaut32.dll", version:"6.0.6000.20732", min_version:"6.0.6000.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Oleaut32.dll", version:"6.0.6000.16607", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Oleaut32.dll", version:"5.2.3790.4202", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Oleaut32.dll", version:"5.2.3790.3057", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Oleaut32.dll", version:"5.1.2600.3266", dir:"\system32", bulletin:bulletin, kb:kb) ||

  hotfix_is_vulnerable(os:"5.0", file:"Oleaut32.dll", version:"2.40.4532.0", dir:"\system32", bulletin:bulletin, kb:kb)
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
