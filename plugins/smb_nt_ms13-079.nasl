#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(69838);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-3868");
  script_bugtraq_id(62184);
  script_osvdb_id(97114);
  script_xref(name:"MSFT", value:"MS13-079");
  script_xref(name:"IAVB", value:"2013-B-0100");

  script_name(english:"MS13-079: Vulnerability in Active Directory Could Allow Denial of Service (2853587)");
  script_summary(english:"Checks the file version of Ntdsatq.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an Active Directory denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote host is affected by a denial of service vulnerability in
Active Directory Services and Active Directory Lightweight Directory
Services (AD LDS).

By sending a specially crafted query to the Lightweight Directory
Access Protocol (LDAP) service, an attacker can cause the directory
service to stop responding until an administrator restarts the
service.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-079");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, and 2012.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS13-079';
kb = '2853587';

kbs = make_list(kb);
if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit('SMB/WindowsVersion', exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# RT is not affected
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);
if ("Windows Embedded" >< productname)
  exit(0, "The host is running "+productname+" and is, therefore, not affected.");

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);

# Determine if Active Directory is enabled.
LDS_Enabled  = FALSE;
NTDS_Enabled = FALSE;

# NTDS check
ntds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\NTDS\Parameters\DSA Database file");
if (!isnull(ntds_value))
  NTDS_Enabled = TRUE;

# LDS check
lds_value = get_registry_value(
  handle:hklm, item:"SYSTEM\CurrentControlSet\Services\DirectoryServices\Performance\InstallType");
if (!isnull(lds_value))
  LDS_Enabled = TRUE;

RegCloseKey(handle:hklm);
close_registry(close:FALSE);

if (!NTDS_Enabled && !LDS_Enabled)
{
  hotfix_check_fversion_end();
  exit(0, "The host is not affected since none of the affected Active Directory products are installed.");
}

########## KB2853587 ###########
#  Windows Vista SP2,          #
#  Windows 7 SP1,              #
#  Windows Server 2008 SP2,    #
#  Windows Server 2008 R2 SP1  #
#  Windows Server 8            #
#  Windows Server 2012         #
################################
if (
  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ntdsatq.dll", version:"6.2.9200.20772", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Ntdsatq.dll", version:"6.2.9200.16664", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Windows 7 and Windows Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntdsatq.dll", version:"6.1.7601.22400", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Ntdsatq.dll", version:"6.1.7601.18219", min_version:"6.1.7600.16521", dir:"\system32", bulletin:bulletin, kb:kb) ||

  # Vista / Windows 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsatq.dll", version:"6.0.6002.23155", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Ntdsatq.dll", version:"6.0.6002.18882", min_version:"6.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:kb)
)
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
