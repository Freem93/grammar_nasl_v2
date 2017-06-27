#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85876);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/11/17 18:50:41 $");
  script_cve_id(
    "CVE-2015-2513",
    "CVE-2015-2514",
    "CVE-2015-2516",
    "CVE-2015-2519",
    "CVE-2015-2530"
  );
  script_bugtraq_id(
    76555,
    76556,
    76557,
    76558,
    76559
  );
  script_osvdb_id(
    127197,
    127198,
    127199,
    127200,
    127201
  );
  script_xref(name:"MSFT", value:"MS15-098");

  script_name(english:"MS15-098: Vulnerabilities in Windows Journal Could Allow Remote Code Execution (3089669)");
  script_summary(english:"Checks the version of journal.dll");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by multiple vulnerabilities in Windows Journal :

  - Multiple remote code execution vulnerabilities exist in
    Windows Journal due to improper handling of specially
    crafted Journal (.jnt) files. A remote, unauthenticated
    attacker can exploit these by convincing a user to open
    a malicious Journal file, resulting in the execution of
    arbitrary code in the context of the current user.
    (CVE-2015-2513, CVE-2015-2514, CVE-2015-2519,
    CVE-2015-2530)

  - A denial of service vulnerability exists in Windows
    Journal due to improper handling of specially crafted
    Journal (.jnt) files. A remote, unauthenticated attacker
    can exploit this by convincing a user to open a
    malicious Journal file, resulting in a loss of data.
    (CVE-2015-2516)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-098");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Vista, 2008, 7, 2008 R2,
8, 2012, 8.1, 2012 R2, and 10.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-098';
kbs = make_list('3081455', '3069114');

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0', win10:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

commonfiles = hotfix_get_commonfilesdir();
if (!commonfiles) commonfiles = hotfix_get_commonfilesdirx86();

if (!commonfiles) audit(AUDIT_PATH_NOT_DETERMINED, 'Common Files');

journal_path = hotfix_append_path(path:commonfiles, value:"\microsoft shared\ink");

if (
  # Windows 10
  hotfix_is_vulnerable(os:"10", sp:0, file:"journal.dll", version:"10.0.10240.16485", min_version:"10.0.10240.16000", path:journal_path, bulletin:bulletin, kb:'3081455') ||
  # Windows 8.1 / Windows Server 2012 R2    

  hotfix_is_vulnerable(os:"6.3", sp:0, file:"journal.dll", version:"6.3.9600.18005", min_version:"6.3.9600.16000", path:journal_path, bulletin:bulletin, kb:"3069114") ||

  # Windows 8 / Windows Server 2012    
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"journal.dll", version:"6.2.9200.21581", min_version:"6.2.9200.20000", path:journal_path, bulletin:bulletin, kb:"3069114") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"journal.dll", version:"6.2.9200.17467", min_version:"6.2.9200.16000", path:journal_path, bulletin:bulletin, kb:"3069114") ||

  # Windows 7 / Server 2008 R2    
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"journal.dll", version:"6.1.7601.23154", min_version:"6.1.7601.22000", path:journal_path, bulletin:bulletin, kb:"3069114") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"journal.dll", version:"6.1.7601.18951", min_version:"6.1.7600.16000", path:journal_path, bulletin:bulletin, kb:"3069114") ||

  # Vista / Windows Server 2008    
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"journal.dll", version:"6.0.6002.23774", min_version:"6.0.6002.23000", path:journal_path, bulletin:bulletin, kb:"3069114") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"journal.dll", version:"6.0.6002.19465", min_version:"6.0.6001.18000", path:journal_path, bulletin:bulletin, kb:"3069114")
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

