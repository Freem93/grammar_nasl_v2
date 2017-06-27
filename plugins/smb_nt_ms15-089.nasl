#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85323);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/16 04:44:42 $");

  script_cve_id("CVE-2015-2476");
  script_bugtraq_id(76234);
  script_osvdb_id(125997);
  script_xref(name:"MSFT", value:"MS15-089");
  script_xref(name:"IAVB", value:"2015-B-0096");

  script_name(english:"MS15-089: Vulnerability in WebDAV Could Allow Information Disclosure (3076949)");
  script_summary(english:"Checks the version of davclnt.dll / webclnt.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by an information disclosure
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an information disclosure
vulnerability in the Microsoft Web Distributed Authoring and
Versioning (WebDAV) client due to explicitly allowing the use of
Secure Socket Layer (SSL) 2.0. A remote attacker can exploit this to
force an encrypted SSL 2.0 session with a WebDAV server that has SSL
2.0 enabled, and use a man-in-the-middle attack to decrypt portions of
the encrypted traffic, resulting in the disclosure of sensitive
information.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-089");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista, 2008, 7,
2008 R2, 8, RT, 2012, 8.1, RT 8.1, and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
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

bulletin = 'MS15-089';
kbs = '3076949';

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:make_list(kbs), severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2', win7:'1', win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

if (hotfix_check_server_core() == 1) audit(AUDIT_WIN_SERVER_CORE);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Windows 8.1 / Windows Server 2012 R2    
  hotfix_is_vulnerable(os:"6.3", sp:0, file:"davclnt.dll", version:"6.3.9600.17923", min_version:"6.3.9600.16000", dir:"\system32", bulletin:bulletin, kb:3076949) ||

  # Windows 8 / Windows Server 2012    
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"davclnt.dll", version:"6.2.9200.21538", min_version:"6.2.9200.20000", dir:"\system32", bulletin:bulletin, kb:3076949) ||
  hotfix_is_vulnerable(os:"6.2", sp:0, file:"davclnt.dll", version:"6.2.9200.17428", min_version:"6.2.9200.16000", dir:"\system32", bulletin:bulletin, kb:3076949) ||

  # Windows 7 / Server 2008 R2    
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"davclnt.dll", version:"6.1.7601.23115", min_version:"6.1.7601.20000", dir:"\system32", bulletin:bulletin, kb:3076949) ||
  hotfix_is_vulnerable(os:"6.1", sp:1, file:"davclnt.dll", version:"6.1.7601.18912", min_version:"6.1.7600.18000", dir:"\system32", bulletin:bulletin, kb:3076949) ||

  # Vista / Windows Server 2008
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"webclnt.dll", version:"6.0.6002.23739", min_version:"6.0.6002.20000", dir:"\system32", bulletin:bulletin, kb:3076949) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"webclnt.dll", version:"6.0.6002.19433", min_version:"6.0.6002.18000", dir:"\system32", bulletin:bulletin, kb:3076949) 
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
