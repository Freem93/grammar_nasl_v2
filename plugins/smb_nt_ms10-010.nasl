#
# (C) Tenable Network Security, Inc.
#

if ( NASL_LEVEL < 3000 ) exit(0);

include("compat.inc");

if (description)
{
 script_id(44420);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/04/23 21:11:58 $");

 script_cve_id("CVE-2010-0026");
 script_bugtraq_id(38113);
 script_osvdb_id(62251);
 script_xref(name:"MSFT", value:"MS10-010");
 script_xref(name:"IAVB", value:"2010-B-0012");

 script_name(english:"MS10-010: Vulnerability in Windows Server 2008 Hyper-V Could Allow Denial of Service (977894)");
 script_summary(english:"Checks version of vid.sys");

 script_set_attribute(
  attribute:"synopsis",
  value:"A local attacker can crash the remote host."
 );
 script_set_attribute(
  attribute:"description",
  value:
"The remote host is affected by a denial of service flaw that exists
in Hyper-V.  A local attacker can leverage this to crash all the VMs
on the remote host.

To successfully exploit this vulnerability, an attacker would need an
account on one of the remote VMs and be able to execute arbitrary code
on it."
 );
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS10-010");
 script_set_attribute(
  attribute:"solution",
  value:"Microsoft has released a set of patches for Windows 2008 and 2008 R2."
 );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"patch_publication_date", value:"2010/02/09");
 script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/09");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"stig_severity", value:"II");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "wmi_enum_server_features.nbin", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS10-010';
kbs = make_list("977894");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'1,2', win7:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

# If Hyper-V is not enabled, the software cannot be exploited.  However, the
# software is still technically vulnerable.  The MS bulletin states:
#
#   This update can be installed manually on affected
#   platforms even if the Hyper-V role is not enabled.
#
# Therefore, we'll check for the patch unconditionally during paranoid scans.
#
# (Hyper-V ID = 20)
#
if (!get_kb_item('WMI/server_feature/20') && report_paranoia < 2)
  exit(0, 'Hyper-V is not enabled, therefore the host is not affected.');

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = "977894";

if (
  # Win2008 R2
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Vid.sys", version:"6.1.7600.16475",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.1", arch:"x64", sp:0, file:"Vid.sys", version:"6.1.7600.20587", min_version:"6.1.7600.20000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||

  # Win2008
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:1, file:"Vid.sys", version:"6.0.6001.18372",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:1, file:"Vid.sys", version:"6.0.6001.22572", min_version:"6.0.6001.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"Vid.sys", version:"6.0.6002.18156",                               dir:"\system32\drivers", bulletin:bulletin, kb:kb) ||
  hotfix_is_vulnerable(os:"6.0", arch:"x64", sp:2, file:"Vid.sys", version:"6.0.6002.22278", min_version:"6.0.6002.22000", dir:"\system32\drivers", bulletin:bulletin, kb:kb)
)
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
