#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23834);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/05/06 17:11:37 $");

 script_cve_id("CVE-2006-5585");
 script_bugtraq_id(21550);
 script_osvdb_id(30812);
 script_xref(name:"MSFT", value:"MS06-075");

 script_name(english:"MS06-075: Vulnerability in Windows Could Allow Elevation of Privilege (926255)");
 script_summary(english:"Determines if hotfix 926255 has been installed");

 script_set_attribute(attribute:"synopsis", value:"A local user can elevate his privileges on the remote host.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Windows System that is
vulnerable to a security flaw that could allow a local user to elevate
his privileges or to crash it (therefore causing a denial of
service).");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-075");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/12/12");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/12/12");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/12");

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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-075';
kb = '926255';

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2', win2003:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_is_vulnerable(os:"5.2", sp:0, file:"Sxs.dll", version:"5.2.3790.599", dir:"\system32", bulletin:bulletin, kb:kb) ||
     hotfix_is_vulnerable(os:"5.1", file:"Sxs.dll", version:"5.1.2600.3019", dir:"\system32", bulletin:bulletin, kb:kb) )
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
