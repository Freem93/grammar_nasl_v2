#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(52585);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/04/23 21:35:40 $");

 script_cve_id("CVE-2011-0029");
 script_bugtraq_id(46678);
 script_osvdb_id(71014);
 script_xref(name:"MSFT", value:"MS11-017");
 script_xref(name:"IAVB", value:"2011-B-0033");
 script_name(english:"MS11-017: Vulnerabilities in Remote Desktop Connection Could Allow Remote Code Execution (2508062)");
 script_summary(english:"Checks for hotfix 2508062");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to execute arbitrary code on the remote host through
the Remote Desktop client.");
 script_set_attribute(attribute:"description", value:
"The remote host contains a version of the Remote Desktop client that
incorrectly restricts the path used for loading external libraries.

If an attacker can trick a user on the affected system into opening a
specially crafted .rdp file located in the same network directory as
a specially crafted dynamic link library (DLL) file, this issue could
be leveraged to execute arbitrary code subject to the user's
privileges.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-017");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows XP, 2003, Vista,
7, 2008, and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2011/03/08");
 script_set_attribute(attribute:"patch_publication_date", value:"2011/03/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/08");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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

bulletin = 'MS11-017';
kbs = make_list("2481109", "2483614", "2483618");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);


get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(xp:'3', win2003:'2', vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # MSRDP 7.0
  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", file:"Mstscax.dll", version:"6.1.7600.20861", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2483614") ||
  hotfix_is_vulnerable(os:"6.1", file:"Mstscax.dll", version:"6.1.7600.16722", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2483614") ||

  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", file:"Mstscax.dll", version:"6.1.7600.20861", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2483614") ||
  hotfix_is_vulnerable(os:"6.0", file:"Mstscax.dll", version:"6.1.7600.16722", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2483614") ||

  # Windows XP SP3
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.1.7600.20861", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:"2483614") ||
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.1.7600.16722", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:"2483614") ||

  # MSRDP 6.0 and 6.1
  # Windows Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mstscax.dll", version:"6.0.6002.22550", min_version:"6.0.6002.22000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Mstscax.dll", version:"6.0.6002.18356", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mstscax.dll", version:"6.0.6001.22815", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||
  hotfix_is_vulnerable(os:"6.0", sp:1, file:"Mstscax.dll", version:"6.0.6001.18564", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||

  # Win2k3 / Windows XP x64
  hotfix_is_vulnerable(os:"5.2", file:"Mstscax.dll", version:"6.0.6001.22815", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||
  hotfix_is_vulnerable(os:"5.2", file:"Mstscax.dll", version:"6.0.6001.18564", min_version:"6.0.6000.0", dir:"\system32", bulletin:bulletin, kb:"2481109") ||

  # Windows XP SP3
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.0.6001.22840", min_version:"6.0.6001.22000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||
  hotfix_is_vulnerable(os:"5.1", file:"Mstscax.dll", version:"6.0.6001.18589", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"2481109") ||
  # MSRDP 5.2
  hotfix_is_vulnerable(os:"5.1", file:"2k3Mstscax.dll", version:"5.2.3790.4807", min_version:"5.2.0.0", dir:"\system32", bulletin:bulletin, kb:"2483618")
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
