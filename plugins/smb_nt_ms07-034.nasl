#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(25487);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id(
  "CVE-2006-2111",
  "CVE-2007-1658",
  "CVE-2007-2225",
  "CVE-2007-2227"
 );
 script_bugtraq_id(17717, 23103, 24392, 24410);
 script_osvdb_id(25073, 34102, 35345, 35346);
 script_xref(name:"MSFT", value:"MS07-034");
 script_xref(name:"CERT", value:"682825");
 script_xref(name:"CERT", value:"783761");
 script_xref(name:"EDB-ID", value:"27745");
 script_xref(name:"EDB-ID", value:"29771");

 script_name(english:"MS07-034: Cumulative Security Update for Outlook Express and Windows Mail (929123)");
 script_summary(english:"Determines the presence of update 929123");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the email
client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Microsoft Outlook Express with
several security flaws that could allow an attacker to execute arbitrary
code on the remote host.

To exploit this flaw, an attacker would need to send a malformed email
to a victim on the remote host and have him open it.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-034");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Outlook Express and Windows
Mail.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(200);

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/28");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/06/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/06/12");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS07-034';
kb = '929123';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", sp:0, file:"Inetcomm.dll", version:"6.0.6000.16480", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Inetcomm.dll", version:"6.0.3790.4073", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.2", sp:1, file:"Inetcomm.dll", version:"6.0.3790.2929", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"5.1", sp:2, file:"Inetcomm.dll", version:"6.0.2900.3138", dir:"\system32", bulletin:bulletin, kb:kb)
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
