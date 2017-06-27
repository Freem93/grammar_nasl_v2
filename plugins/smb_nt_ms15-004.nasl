#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(80493);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/06 17:11:39 $");

  script_cve_id("CVE-2015-0016");
  script_bugtraq_id(71965);
  script_osvdb_id(116958);
  script_xref(name:"EDB-ID", value:"35983");
  script_xref(name:"MSFT", value:"MS15-004");
  script_xref(name:"IAVA", value:"2015-A-0010");

  script_name(english:"MS15-004: Vulnerability in Windows Components Could Allow Elevation of Privilege (3025421)");
  script_summary(english:"Checks the version of TSWbPrxy.exe.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the TS WebProxy Windows component due to a failure to
properly sanitize file paths. An attacker can exploit this to gain the
same rights as the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-004");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 7, 2008 R2,
8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS15-004 Microsoft Remote Desktop Services Web Proxy IE Sandbox Escape');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/13");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS15-004';
kbs  = make_list(
  "3023299",
  "3019978",
  "3020387",
  "3020388"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

# Windows Server 2008 is not affected. Vista and 2008 R2 are affected.
if ("Server 2008" >< productname && "Server 2008 R2" >!< productname && "Small Business Server 2011" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

vuln = 0;

##############
# KB 3023299 #
##############
if (
  # Vista only
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"TSWbPrxy.exe", version:"6.1.7600.21909", min_version:"6.1.7600.20000", dir:"\system32", bulletin:bulletin, kb:'3023299') ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"TSWbPrxy.exe", version:"6.1.7600.17715", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'3023299')
) vuln++;

##############
# KB 3019978 #
##############
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"TSWbPrxy.exe", version:"6.1.7601.22907", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:'3019978') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"TSWbPrxy.exe", version:"6.1.7601.18699", min_version:"6.1.7600.16000", dir:"\system32", bulletin:bulletin, kb:'3019978') ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"TSWbPrxy.exe", version:"6.2.9200.21329", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:'3019978') ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"TSWbPrxy.exe", version:"6.2.9200.17213", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3019978') ||

  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"TSWbPrxy.exe", version:"6.3.9600.17555", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3019978')
) vuln++;

##############
# KB 3020387 #
##############
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"TSWbPrxy.exe", version:"6.2.9200.21329", min_version:"6.2.9600.20000", dir:"\system32", bulletin:bulletin, kb:'3020387') ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"TSWbPrxy.exe", version:"6.2.9200.17212", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:'3020387')
) vuln++;

##############
# KB 3020388 #
##############
if (
  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"TSWbPrxy.exe", version:"6.3.9600.17553", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:'3020388')
) vuln++;

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
