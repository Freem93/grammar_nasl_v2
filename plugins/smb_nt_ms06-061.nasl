#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(22534);
 script_version("$Revision: 1.46 $");
 script_cvs_date("$Date: 2016/06/30 19:55:38 $");

 script_cve_id("CVE-2006-4685", "CVE-2006-4686");
 script_bugtraq_id(20338, 20339);
 script_osvdb_id(29425, 29426);
 script_xref(name:"CERT", value:"547212");
 script_xref(name:"MSFT", value:"MS06-061");

 script_name(english:"MS06-061: Vulnerabilities in Microsoft XML Core Services Could Allow Remote Code Execution (924191)");
 script_summary(english:"Determines the presence of update 924191");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through the web or
email client.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Windows that contains a flaw
in the Windows XML Core Services.

An attacker may be able to execute arbitrary code on the remote host
by constructing a malicious script and enticing a victim to visit a
website or view a specially crafted email message.");
 script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms06-061");
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and
2003.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS06-071 Microsoft Internet Explorer XML Core Services HTTP Request Handling');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value:"2006/11/08");
 script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/10");

 script_set_attribute(attribute:"plugin_type", value:"local");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:xml_core_services");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
 script_family(english:"Windows : Microsoft Bulletins");

 script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
 script_require_keys("SMB/MS_Bulletin_Checks/Possible");
 script_require_ports(139, 445, 'Host/patch_management_checks');
 exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS06-061';
kbs = make_list("924191", "924424");
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(win2k:'4,5', xp:'1,2', win2003:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

share = hotfix_path2share(path:rootfile);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

kb = '924191';

if ( ( hotfix_check_fversion(file:"system32\Msxml3.dll", version:"8.70.1113.0", bulletin:bulletin, kb:'924191') == HCF_OLDER ) ||
     ( hotfix_check_fversion(file:"system32\Msxml4.dll", version:"4.20.9839.0", bulletin:bulletin, kb:'925672') == HCF_OLDER ) ||
     ( hotfix_check_fversion(file:"system32\Msxml5.dll", version:"5.10.2930.0", bulletin:bulletin, kb:'924424') == HCF_OLDER ) ||
     ( hotfix_check_fversion(file:"system32\Msxml6.dll", version:"6.0.3888.0", bulletin:bulletin, kb:'925673') == HCF_OLDER ) )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();

  hotfix_check_fversion_end();
  exit(0);
}

office_versions = hotfix_check_office_version ();
if ( !office_versions )
  exit(0);

rootfiles = hotfix_get_commonfilesdir();
if ( ! rootfiles )
  exit(0);

if (!office_versions["11.0"])
  exit (0);

share = hotfix_path2share(path:rootfiles["11.0"]);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if ( hotfix_check_fversion(path:rootfiles["11.0"], file:"\Microsoft Shared\Office11\msxml5.dll", version:"5.10.2930.0", bulletin:bulletin, kb:'924424') == HCF_OLDER )
{
  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  hotfix_security_hole();
  exit(0);
}
else
{
  hotfix_check_fversion_end();
  audit(AUDIT_HOST_NOT, 'affected');
}
