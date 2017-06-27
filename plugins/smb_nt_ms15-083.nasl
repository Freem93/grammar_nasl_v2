#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85321);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/09/19 13:53:09 $");
  script_cve_id("CVE-2015-2474");
  script_bugtraq_id(76220);
  script_osvdb_id(125989);
  script_xref(name:"TRA", value:"TRA-2015-01");
  script_xref(name:"MSFT", value:"MS15-083");

  script_name(english:"MS15-083: Vulnerability in Server Message Block Could Allow Remote Code Execution (3073921)");
  script_summary(english:"Checks the version of srv.sys.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote code execution vulnerability.");
  script_set_attribute(attribute:"description", value:
"A remote code execution vulnerability exists in Windows due to
improper handling of Server Message Block (SMB) logging activities. An
authenticated, remote attacker can exploit this vulnerability to cause
a memory corruption issue, resulting in the execution of arbitrary
code in the context of the current user.");
  script_set_attribute(attribute:"see_also", value:"https://www.tenable.com/security/research/tra-2015-01");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-083");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Vista and 2008.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/11");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
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

bulletin = 'MS15-083';
kbs = '3073921';

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:make_list(kbs), severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

if (hotfix_check_sp_range(vista:'2') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

share = hotfix_get_systemdrive(as_share:TRUE, exit_on_fail:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

if (
  # Vista / Windows Server 2008    
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srv.sys", version:"6.0.6002.23788", min_version:"6.0.6002.20000", dir:"\system32\drivers", bulletin:bulletin, kb:3073921) ||
  hotfix_is_vulnerable(os:"6.0", sp:2, file:"srv.sys", version:"6.0.6002.19478", min_version:"6.0.6002.18000", dir:"\system32\drivers", bulletin:bulletin, kb:3073921)
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

