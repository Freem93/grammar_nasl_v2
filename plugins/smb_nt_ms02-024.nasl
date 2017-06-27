#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10964);
 script_version("$Revision: 1.38 $");
 script_cvs_date("$Date: 2017/05/26 15:15:35 $");

 script_cve_id("CVE-2002-0367");
 script_bugtraq_id(4287);
 script_osvdb_id(788);
 script_xref(name:"MSFT", value:"MS02-024");
 script_xref(name:"MSKB", value:"320206");

 script_name(english:"MS02-024: Windows Debugger flaw can Lead to Elevated Privileges (320206)");
 script_summary(english:"Checks for MS Hotfix Q320206, Elevated Privilege");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a flaw in the Windows Debugger that could
allow a local user to elevate his privileges.

To exploit this vulnerability, a user needs to send a specially crafted
code to the Debbuging handler to execute arbitrary code with SYSTEM
privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms02-024");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows NT and 2000.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
 script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/03/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2002/05/22");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/05/23");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2002-2017 Tenable Network Security, Inc.");
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

bulletin = 'MS02-024';
kb = '320206';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(nt:'6', win2k:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"5.0", file:"Smss.exe", version:"5.0.2195.5695", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"4.0", file:"Smss.exe", version:"4.0.1381.7152", dir:"\system32", bulletin:bulletin, kb:kb)
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


