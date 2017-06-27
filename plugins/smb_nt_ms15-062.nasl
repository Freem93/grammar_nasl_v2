#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(84060);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/06/16 21:09:22 $");

  script_cve_id("CVE-2015-1757");
  script_bugtraq_id(75023);
  script_osvdb_id(123077);
  script_xref(name:"MSFT", value:"MS15-062");
  script_xref(name:"IAVB", value:"2015-B-0072");

  script_name(english:"MS15-062: Vulnerability in Active Directory Federation Services Could Allow Elevation of Privilege (3062577)");
  script_summary(english:"Checks the version of a DLL file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a privilege escalation
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an XSS elevation of privilege
vulnerability in Active Directory Federation Services (AD FS) due to
improper sanitization of user-supplied input. A remote attacker can
exploit this by submitting a specially crafted URL to a target site,
resulting in the execution of malicious script code in the security
context of the user or the ability to conduct further cross-site
scripting attacks.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-062");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2008,
2008 R2, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-062';
kb = '3062577';
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

# Server core is not affected
if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

# 2008, 2008 r2, and 2012 are affected
# exclude 2012 r2, vista, and 7
if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if (
  "Server 2012 R2" >< productname ||
  ("2012" >!< productname &&
   "2008" >!< productname)
) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"microsoft.identityserver.dll", version:"6.2.9200.17366", min_version:"6.2.9200.16000", dir:"\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"microsoft.identityserver.dll", version:"6.2.9200.21478", min_version:"6.2.9200.20000", dir:"\Microsoft.NET\assembly\GAC_MSIL\Microsoft.IdentityServer\v4.0_6.2.0.0__31bf3856ad364e35", bulletin:bulletin, kb:kb) ||

  # Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"microsoft.identityserver.dll", version:"6.1.7601.23049", min_version:"6.1.7601.22000", dir:"\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"microsoft.identityserver.dll", version:"6.1.7601.18847", min_version:"6.1.7600.18000", dir:"\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35", bulletin:bulletin, kb:kb) ||

  # Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"microsoft.identityserver.dll", version:"6.1.7601.23049", min_version:"6.1.7601.22000", dir:"\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, arch:"x64", file:"microsoft.identityserver.dll", version:"6.1.7601.18847", min_version:"6.1.7600.18000", dir:"\assembly\GAC_MSIL\Microsoft.IdentityServer\6.1.0.0__31bf3856ad364e35", bulletin:bulletin, kb:kb)
)
{
  set_kb_item(name:'www/0/XSS', value:TRUE);
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
