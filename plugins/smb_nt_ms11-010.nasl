#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(51910);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2015/04/23 21:35:40 $");

 script_cve_id("CVE-2011-0030");
 script_bugtraq_id(46142);
 script_osvdb_id(70826);
 script_xref(name:"MSFT", value:"MS11-010");

 script_name(english:"MS11-010: Vulnerability in Windows Client/Server Run-time Subsystem Could Allow Elevation of Privilege (2476687)");
 script_summary(english:"Checks version of Csrsv.dll");

 script_set_attribute(  attribute:"synopsis", value:
"Users can elevate their privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host allows elevation of privileges in its Windows
Client/Server run-time subsystem (CSRSS) because it may be possible to
create a specially crafted application that continues to run after the
attacker logs off.

An attacker might exploit this to run arbitrary code in kernel mode.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-010");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/02/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/02/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Windows : Microsoft Bulletins");

 script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS11-010';
kb = "2476687";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 2003 and XP x64
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Csrsrv.dll", version:"5.2.3790.4803", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows XP x86
  hotfix_is_vulnerable(os:"5.1", sp:3, file:"Csrsrv.dll", version:"5.1.2600.6055", dir:"\system32", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
