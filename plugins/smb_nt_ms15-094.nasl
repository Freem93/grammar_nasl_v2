#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85845);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");
  script_cve_id(
    "CVE-2015-2483",
    "CVE-2015-2484",
    "CVE-2015-2485",
    "CVE-2015-2486",
    "CVE-2015-2487",
    "CVE-2015-2489",
    "CVE-2015-2490",
    "CVE-2015-2491",
    "CVE-2015-2492",
    "CVE-2015-2493",
    "CVE-2015-2494",
    "CVE-2015-2496",
    "CVE-2015-2498",
    "CVE-2015-2499",
    "CVE-2015-2500",
    "CVE-2015-2501",
    "CVE-2015-2541",
    "CVE-2015-2542"
  );
  script_bugtraq_id(
    76570,
    76571,
    76572,
    76573,
    76574,
    76575,
    76576,
    76577,
    76578,
    76579,
    76580,
    76581,
    76582,
    76583,
    76584,
    76585,
    76586
  );
  script_osvdb_id(
    127167,
    127168,
    127169,
    127170,
    127171,
    127172,
    127173,
    127174,
    127175,
    127176,
    127177,
    127178,
    127179,
    127180,
    127181,
    127182,
    127183,
    148624
  );
  script_xref(name:"MSFT", value:"MS15-094");

  script_name(english:"MS15-094: Cumulative Security Update for Internet Explorer (3089548)");
  script_summary(english:"Checks the version of mshtml.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Internet Explorer installed on the remote host is
missing Cumulative Security Update 3089548. It is, therefore, affected
by multiple vulnerabilities, the majority of which are remote code
execution vulnerabilities. An unauthenticated, remote attacker can
exploit these issues by convincing a user to visit a specially crafted
website, resulting in the execution of arbitrary code in the context
of the current user.

Note that the majority of the vulnerabilities addressed by Cumulative
Security Update 3089548 are mitigated by the Enhanced Security
Configuration (ESC) mode which is enabled by default on Windows Server
2003, 2008, 2008 R2, 2012, and 2012 R2.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-094");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
8, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/08");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:ie");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS15-094';
kbs = make_list('3087038', '3081455');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"mshtml.dll", version:"11.0.10240.16485", min_version:"11.0.10240.16000", dir:"\system32", bulletin:bulletin, kb:"3081455") ||

  # Windows 8.1 / Windows Server 2012 R2
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"mshtml.dll", version:"11.0.9600.18036", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||

  # Windows 8 / Windows Server 2012
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.21605", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"mshtml.dll", version:"10.0.9200.17492", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||

  # Windows 7 / Server 2008 R2
  # Internet Explorer 10
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.21605", min_version:"10.0.9200.21000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"10.0.9200.17492", min_version:"10.0.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  # Internet Explorer 11
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"11.0.9600.18015", min_version:"11.0.9600.17000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.23172", min_version:"8.0.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"8.0.7601.18969", min_version:"8.0.7601.17000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.20811", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"mshtml.dll", version:"9.0.8112.16696", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||

  # Vista / Windows Server 2008
  # Internet Explorer 7
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.23788", min_version:"7.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"7.0.6002.19478", min_version:"7.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  # Internet Explorer 8
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.23739", min_version:"8.0.6001.23000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"8.0.6001.19679", min_version:"8.0.6001.18000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  # Internet Explorer 9
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.20811", min_version:"9.0.8112.20000", dir:"\system32", bulletin:bulletin, kb:"3087038") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"mshtml.dll", version:"9.0.8112.16696", min_version:"9.0.8112.16000", dir:"\system32", bulletin:bulletin, kb:"3087038")
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
