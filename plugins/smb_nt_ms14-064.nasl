#
# (C) Tenable Network Security, Inc.
#

include('compat.inc');

if (description)
{
  script_id(79125);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/09 21:04:54 $");

  script_cve_id("CVE-2014-6332", "CVE-2014-6352");
  script_bugtraq_id(70690, 70952);
  script_osvdb_id(113140, 114533);
  script_xref(name:"CERT", value:"158647");
  script_xref(name:"EDB-ID", value:"35229");
  script_xref(name:"MSFT", value:"MS14-064");

  script_name(english:"MS14-064: Vulnerabilities in Windows OLE Could Allow Remote Code Execution (3011443)");
  script_summary(english:"Checks the versions of packager.dll and Oleaut32.dll.");

  script_set_attribute(attribute:"synopsis", value:"The remote Windows host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by multiple vulnerabilities :

  - A remote code execution vulnerability due to Internet
    Explorer improperly handling access to objects in
    memory. A remote attacker can exploit this vulnerability
    by convincing a user to visit a specially crafted
    website in Internet Explorer, resulting in execution of
    arbitrary code in the context of the current user.
    (CVE-2014-6332)

  - A remote code execution vulnerability due to a flaw in
    the OLE package manager. A remote attacker can exploit
    this vulnerability by convincing a user to open an
    Office file containing specially crafted OLE objects,
    resulting in execution of arbitrary code in the context
    of the current user. (CVE-2014-6352)");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-064");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2003, Vista, 2008,
7, 2008 R2, 8, 2012, 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS14-064 Microsoft Windows OLE Package Manager Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_set_attribute(attribute:"vuln_publication_date", value:"2014/10/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

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

bulletin = 'MS14-064';
kbs = make_list(
  "3006226",
  "3010788"
);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2003:'2', vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"packager.dll", version:"6.3.9600.17408", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||

  # KB 3006226
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"Oleaut32.dll", version:"6.3.9600.17403", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||

  # Windows 8 / Windows Server 2012
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"packager.dll", version:"6.2.9200.21278", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"packager.dll", version:"6.2.9200.17160", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||

  # KB 3006226
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Oleaut32.dll", version:"6.2.9200.21273", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"Oleaut32.dll", version:"6.2.9200.17155", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||

  # Windows 7 / Server 2008 R2
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"packager.dll", version:"6.1.7601.22853", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"packager.dll", version:"6.1.7601.18645", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||

  # KB 3006226
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.22846", min_version:"6.1.7601.22000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"Oleaut32.dll", version:"6.1.7601.18640", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"packager.dll", version:"6.0.6002.23527", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"packager.dll", version:"6.0.6002.19220", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3010788") ||

  # KB 3006226
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.23523", min_version:"6.0.6002.23000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"Oleaut32.dll", version:"6.0.6002.19216", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:"3006226") ||

  # Windows Server 2003
  hotfix_is_vulnerable(os:"5.2", sp:2, file:"Oleaut32.dll", version:"5.2.3790.5464", dir:"\system32", bulletin:bulletin, kb:"3006226")
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
