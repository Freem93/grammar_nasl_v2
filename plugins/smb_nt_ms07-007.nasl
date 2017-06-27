#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(24331);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2015/04/23 21:11:56 $");

 script_cve_id("CVE-2007-0210");
 script_bugtraq_id(22499);
 script_osvdb_id(31889);
 script_xref(name:"MSFT", value:"MS07-007");

 script_name(english:"MS07-007: Vulnerability in Windows Image Acquisition Service Could Allow Elevation of Privilege (927802)");
 script_summary(english:"Determines the presence of update 927802");

 script_set_attribute(attribute:"synopsis", value:
"Vulnerabilities in the Windows Acquisition Service may allow a user to
elevate privileges.");
 script_set_attribute(attribute:"description", value:
"The remote version of Windows contains a version of the Image
Acquisition service that contains a vulnerability in the way it starts
applications.  An authenticated user may exploit this vulnerability to
elevate privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-007");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/02/13");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/13");

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
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS07-007';
kb = "927802";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wiaservc.dll", version:"5.1.2600.3051", dir:"\system32", bulletin:bulletin, kb:kb))
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
