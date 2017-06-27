#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86819);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2017/03/09 14:56:42 $");

  script_cve_id(
    "CVE-2015-2427",
    "CVE-2015-6064",
    "CVE-2015-6065",
    "CVE-2015-6066",
    "CVE-2015-6068",
    "CVE-2015-6069",
    "CVE-2015-6070",
    "CVE-2015-6071",
    "CVE-2015-6072",
    "CVE-2015-6073",
    "CVE-2015-6074",
    "CVE-2015-6075",
    "CVE-2015-6076",
    "CVE-2015-6077",
    "CVE-2015-6078",
    "CVE-2015-6079",
    "CVE-2015-6080",
    "CVE-2015-6081",
    "CVE-2015-6082",
    "CVE-2015-6084",
    "CVE-2015-6085",
    "CVE-2015-6086",
    "CVE-2015-6087",
    "CVE-2015-6088",
    "CVE-2015-6089"
  );
  script_bugtraq_id(
    77439,
    77440,
    77441,
    77442,
    77443,
    77444,
    77445,
    77446,
    77447,
    77448,
    77449,
    77450,
    77451,
    77452,
    77453,
    77454,
    77455,
    77456,
    77457,
    77459,
    77461,
    77467,
    77468,
    77469,
    77470
  );
  script_osvdb_id(
    130017,
    130018,
    130019,
    130020,
    130021,
    130022,
    130023,
    130024,
    130025,
    130026,
    130027,
    130028,
    130029,
    130030,
    130031,
    130032,
    130033,
    130034,
    130035,
    130036,
    130037,
    130038,
    130039,
    130040,
    130041
  );
  script_xref(name:"MSFT", value:"MS15-112");

  script_name(english:"MS15-112: Cumulative Security Update for Internet Explorer (3104517)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web browser installed that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3104517. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these issues by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-112");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/10");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

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

bulletin = 'MS15-112';
kbs = make_list('3100773', '3105213', '3105211');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10586.3", min_version:"11.0.10586.0", dir:"\system32", bulletin:bulletin, kb:"3105211") ||
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.16590", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3105213") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18098", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||

  # Windows 8 / Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21673", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17556", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.21673", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.17556", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18098", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23244", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.19038", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.20832", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16717", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||

  # Vista / Windows Server 2008
  # Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.23830", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.19520", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.23758", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.19698", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20832", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3100773") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16717", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3100773")
)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
