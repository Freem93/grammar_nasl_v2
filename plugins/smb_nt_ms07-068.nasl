#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(29312);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/01/28 22:37:17 $");

 script_cve_id("CVE-2007-0064");
 script_bugtraq_id(26776);
 script_osvdb_id(39122);
 script_xref(name:"IAVA", value:"2007-A-0056");
 script_xref(name:"MSFT", value:"MS07-068");
 script_xref(name:"CERT", value:"319385");

 script_name(english:"MS07-068: Vulnerability in Windows Media File Format Could Allow Remote Code Execution (941569 / 944275)");
 script_summary(english:"Checks the version of Media Format");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media
File Format.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player/Service.

There is a vulnerability in the remote version of this software that
could allow an attacker to execute arbitrary code on the remote host.

To exploit this flaw, one attacker would need to set up a rogue ASF file
and send it to a victim on the remote host.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS07-068");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003 and
Vista.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);

 script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"patch_publication_date", value:"2007/12/11");
 script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_format_runtime");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:windows_media_services");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS07-068';
kbs = make_list("941569", "944275");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  hotfix_is_vulnerable(os:"6.0", file:"wmasf.dll", version:"11.0.6000.6345", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||

  hotfix_is_vulnerable(os:"5.2", sp:1, file:"wmsserver.dll", version:"9.1.1.3844", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'944275') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"wmsserver.dll", version:"9.1.1.3862", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'944275') ||
  hotfix_is_vulnerable(os:"5.2", sp:1, arch:"x86", file:"wmasf.dll", version:"10.0.0.3710", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"wmasf.dll", version:"10.0.0.4000", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.2", sp:1, arch:"x64", file:"wwmasf.dll", version:"10.0.0.3710", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"wwmasf.dll", version:"10.0.0.4000", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.2", arch:"x64", file:"wmasf.dll", version:"10.0.0.3811", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||

  hotfix_is_vulnerable(os:"5.1", file:"wmasf.dll", version:"9.0.0.3267", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.1", file:"wmasf.dll", version:"10.0.0.4060", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.1", file:"wmasf.dll", version:"11.0.5721.5238", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||

  hotfix_is_vulnerable(os:"5.0", file:"wmasf.dll", version:"7.10.0.3081", min_version:"7.10.0.0", dir:"\system32", bulletin:bulletin, kb:'941569') ||
  hotfix_is_vulnerable(os:"5.0", file:"wmasf.dll", version:"9.0.0.3267", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:'941569')
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
