#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91011);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/07/13 20:59:28 $");
  
  script_cve_id("CVE-2016-0178");
  script_bugtraq_id(90032);
  script_osvdb_id(138331);
  script_xref(name:"MSFT", value:"MS16-061");
  script_xref(name:"IAVA", value:"2016-A-0130");

  script_name(english:"MS16-061: Security Update for Microsoft RPC (3155520)");
  script_summary(english:"Checks the version of rpcrt4.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a remote code execution
vulnerability in the Microsoft RPC Network Data Representation (NDR)
Engine due to improper handling of memory. An authenticated, remote
attacker can exploit this vulnerability, via malformed RPC requests,
to execute arbitrary code.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS16-061");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-061';

kbs = make_list("3153171","3153704","3156387","3156421");

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0',win10:'0') <= 0)
  audit(AUDIT_OS_SP_NOT_VULN);

# EOL Operating Systems
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

if ("Windows 8" >< productname && "8.1" >!< productname)
  audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"Rpcrt4.dll", version:"10.0.10240.16841", min_version:"10.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3156387") || 
  hotfix_is_vulnerable(os:"10", sp:0, file:"Rpcrt4.dll", version:"10.0.10586.306", min_version:"10.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3156421") ||

  # Windows 8.1 / 2012 R2
  hotfix_is_vulnerable(os:"6.3", file:"Rpcrt4.dll", version:"6.3.9600.18292", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3153704') ||

  # Windows 8 / 2012
  hotfix_is_vulnerable(os:"6.2", file:"Rpcrt4.dll", version:"6.2.9200.21826", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3153704") ||

  # Windows 7 / 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Rpcrt4.dll", version:"6.1.7601.23418", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:'3153171') ||

  # Vista / 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rpcrt4.dll", version:"6.0.6002.23950", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:'3153171') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Rpcrt4.dll", version:"6.0.6002.19598", min_version:"6.0.6002.16000", dir:"\system32", bulletin:bulletin, kb:'3153171')

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
