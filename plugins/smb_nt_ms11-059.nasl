#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55789);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/04/23 21:35:41 $");

  script_cve_id("CVE-2011-1975");
  script_bugtraq_id(49026);
  script_osvdb_id(74408);
  script_xref(name:"MSFT", value:"MS11-059");
  script_xref(name:"IAVB", value:"2011-B-0101");

  script_name(english:"MS11-059: Vulnerability in Microsoft Data Access Components Could Allow Remote Code Execution (2560656)");
  script_summary(english:"Checks the version of Msdaosp.dll");

  script_set_attribute(attribute:"synopsis", value:
"Arbitrary code can be executed on the remote host through Microsoft
Data Access Components.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft Data Access Components (MDAC) installed on
the remote Windows host is affected by a code execution vulnerability.
By tricking a user into opening a legitimate Excel file that is in the
same directory as a specially crafted library file, a remote,
unauthenticated user could execute arbitrary code on the host subject
to the privileges of the user running the affected application.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms11-059");
  script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for Windows 7 and 2008 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
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

bulletin = 'MS11-059';
kb = "2560656";

kbs = make_list(kb);
if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_HOLE);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);

rootfile = hotfix_get_systemroot();
if (!rootfile) exit(1, "Failed to get the system root.");

if (hotfix_check_sp_range(win7:'0,1') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();
port   = kb_smb_transport();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, "smb_session_init");

hcf_init = TRUE;

share = hotfix_path2share(path:rootfile);
path  = ereg_replace(pattern:'^[A-Za-z](.*)', replace:'\\1', string:rootfile);


rc = NetUseAdd(login:login, password:pass, domain:domain, share:share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, share);
}

vuln = 0;
winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:'\\1\\WinSxS', string:rootfile);
files = list_dir(basedir:winsxs, level:0, dir_pat:'simple-provider-dll', file_pat:'^msdaosp\\.dll$');

versions = make_list('6.1.7600.16833', '6.1.7600.20987', '6.1.7601.17632', '6.1.7601.21747');
max_versions = make_list('6.1.7600.20000', '6.1.7600.99999', '6.1.7601.20000', '6.1.7601.99999');
vuln += hotfix_check_winsxs(os:'6.1.', files:files, versions:versions, max_versions:max_versions, bulletin:bulletin, kb:kb);

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_hole();
  hotfix_check_fversion_end();
  exit(0);
}
hotfix_check_fversion_end();
audit(AUDIT_HOST_NOT, 'affected');
