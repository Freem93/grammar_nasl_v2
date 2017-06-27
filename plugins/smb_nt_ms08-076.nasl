#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(35075);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2016/12/09 20:55:00 $");

 script_cve_id("CVE-2008-3009", "CVE-2008-3010");
 script_bugtraq_id(32653, 32654);
 script_osvdb_id(50558, 50559);
 script_xref(name:"MSFT", value:"MS08-076");
 script_xref(name:"IAVB", value:"2008-B-0081");

 script_name(english:"MS08-076: Vulnerabilities in Windows Media Components Could Allow Remote Code Execution (959807)");
 script_summary(english:"Checks the version of Media Format");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the Media
Components.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Windows Media Player/Components.

There is a vulnerability in the remote version of this software that may
allow an attacker to execute arbitrary code on the remote host thru
flaws in ISATAP and SPN.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms08-076");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP, 2003,
Vista and Windows 2008.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(200, 255);

 script_set_attribute(attribute:"vuln_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2008/12/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2008/12/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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

bulletin = 'MS08-076';
kbs = make_list("952068", "952069", "954600");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'2,3', win2003:'1,2', vista:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

e = 0;

# WMP
kb = '954600';
e += hotfix_is_vulnerable(os:"5.0", file:"Strmdll.dll", version:"4.1.0.3937", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", file:"Strmdll.dll", version:"4.1.0.3937", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.2", file:"Strmdll.dll", version:"4.1.0.3937", dir:"\system32", bulletin:bulletin, kb:kb);

# WMF Runtime and WMS on Vista/2k8
kb = '952069';
e += hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wmvcore.dll", version:"11.0.6001.7105", min_version:"11.0.6001.7100", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"6.0", sp:1, file:"Wmvcore.dll", version:"11.0.6001.7001", min_version:"11.0.6001.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"6.0", sp:0, file:"Wmvcore.dll", version:"11.0.6000.6346", min_version:"11.0.6000.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"6.0", sp:0, file:"Wmvcore.dll", version:"11.0.6000.6505", min_version:"11.0.6000.6500", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"6.0", file:"Wmsserver.dll", version:"9.5.6001.18161", dir:"\system32", bulletin:bulletin, kb:kb);

# WMS on 2k3
kb = '952068';
e += hotfix_is_vulnerable(os:"5.2", sp:2, file:"Wmsserver.dll", version:"9.1.1.5000", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.2", sp:1, file:"Wmsserver.dll", version:"9.1.1.3845", dir:"\system32", bulletin:bulletin, kb:kb);

# WMF Runtime on 2k3 and XP x64
kb = '952069';
e += hotfix_is_vulnerable(os:"5.2", sp:1, arch:"x86", file:"Wmvcore.dll", version:"10.0.0.3711", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x86", file:"Wmvcore.dll", version:"10.0.0.4001", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.2", sp:1, arch:"x64", file:"Wmvcore.dll", version:"10.0.0.3711", min_version:"10.0.0.0", dir:"\syswow64", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.2",       arch:"x64", file:"Wmvcore.dll", version:"10.0.0.3816", min_version:"10.0.0.3800", dir:"\syswow64", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.2", sp:2, arch:"x64", file:"Wmvcore.dll", version:"10.0.0.4001", min_version:"10.0.0.3900", dir:"\syswow64", bulletin:bulletin, kb:kb);

# 32-bit WMF Runtime on XP x64
kb = '952069';
e += hotfix_is_vulnerable(os:"5.2",       arch:"x64", file:"Wmvcore.dll", version:"11.0.5721.5251", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);

# WMF Runtime on XP SP3
kb = '952069';
e += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Wmvcore.dll", version:"9.0.0.4504", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Wmvcore.dll", version:"10.0.0.3703", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Wmvcore.dll", version:"10.0.0.4066", min_version:"10.0.0.4000", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Wmvcore.dll", version:"10.0.0.4362", min_version:"10.0.0.4300", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:3, file:"Wmvcore.dll", version:"11.0.5721.5251", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);

# WMF Runtime on XP SP2
kb = '952069';
e += hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wmvcore.dll", version:"9.0.0.3268", min_version:"9.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wmvcore.dll", version:"9.0.0.3358", min_version:"9.0.0.3300", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wmvcore.dll", version:"10.0.0.3703", min_version:"10.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wmvcore.dll", version:"10.0.0.4066", min_version:"10.0.0.4000", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wmvcore.dll", version:"10.0.0.4362", min_version:"10.0.0.4300", dir:"\system32", bulletin:bulletin, kb:kb);
e += hotfix_is_vulnerable(os:"5.1", sp:2, file:"Wmvcore.dll", version:"11.0.5721.5251", min_version:"11.0.0.0", dir:"\system32", bulletin:bulletin, kb:kb);

# WMS on w2k
kb = '952068';
e += hotfix_is_vulnerable(os:"5.0", file:"Wmvcore.dll", version:"9.0.0.3268", dir:"\system32", bulletin:bulletin, kb:kb);
e +=  hotfix_is_vulnerable(os:"5.0", file:"Nscm.exe", version:"4.1.0.3936", bulletin:bulletin, kb:kb);


if (e)
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
