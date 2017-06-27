#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29311);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2015/05/07 12:06:03 $");

 script_cve_id("CVE-2007-5587");
 script_bugtraq_id(26121);
 script_osvdb_id(41429);
 script_xref(name:"MSFT", value:"MS07-067");
 script_xref(name:"EDB-ID", value:"30680");

 script_name(english:"MS07-067: Vulnerability in Macrovision Driver Could Allow Local Elevation of Privilege (944653)");
 script_summary(english:"Determines the presence of update 944653");

 script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a kernel driver that is prone to a
local privilege escalation attack.");
 script_set_attribute(attribute:"description", value:
"Macrovision SafeDisc, a copy-protection application for Microsoft
Windows, is installed on the remote host.

The 'SECDRV.SYS' driver included with the version of SafeDisc currently
installed on the remote host enables a local user to gain SYSTEM
privileges using a specially crafted argument to the METHOD_NEITHER
IOCTL.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-067");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows XP and 2003.");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');
 script_cwe_id(119,264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/10/17");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "macrovision_secdrv_priv_escalation.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS07-067';
kb = "944653";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'2', win2003:'1,2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;
if (hotfix_check_sp_range(xp:'2') > 0)
{
  if (get_kb_item("Host/SMB/secdrv/CVE-2007-5587"))
  {
    vuln++;
    hotfix_add_report(bulletin:bulletin, kb:kb);
  }
}
else if (hotfix_check_sp_range(win2003:'1,2') > 0)
{
  if (hotfix_is_vulnerable(os:"5.2", file:"secdrv.sys", version:"4.3.86.0", dir:"\system32\drivers", bulletin:bulletin, kb:kb)) vuln++;
  hotfix_check_fversion_end();
}

if (vuln)
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
