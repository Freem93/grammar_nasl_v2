#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88652);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/31 19:21:53 $");

  script_cve_id("CVE-2016-0037");
  script_osvdb_id(134325);
  script_xref(name:"MSFT", value:"MS16-020");
  script_xref(name:"IAVB", value:"2016-B-0023");

  script_name(english:"MS16-020: Security Update for Active Directory Federation Services to Address Denial of Service (3134222)");
  script_summary(english:"Checks the version of a DLL file.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a denial of service
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is missing a security update. It is,
therefore, affected by a denial of service vulnerability in Active
Directory Federation Services (ADFS) due to a failure to properly
process certain input during forms-based authentication. A remote
attacker can exploit this, via crafted input, to cause the server to
become unresponsive.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms16-020");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows Server 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "wmi_enum_server_features.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS16-020';
kb = '3134222';
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
get_kb_item_or_exit("SMB/WindowsVersion", exit_code:1);
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

# Only 2012 R2
if (hotfix_check_sp_range(win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);
if ("Server 2012 R2" >!< productname) audit(AUDIT_OS_SP_NOT_VULN);

# Only ADFS on Server Core
core_adfs_is_present = FALSE;
if (hotfix_check_server_core() == 1)
{
  features = get_kb_list("WMI/server_feature/*");
  foreach key (keys(features))
  {
    if (features[key] == "Active Directory Federation Services")
    {
      core_adfs_is_present = TRUE;
      break;
    }
  }
  if (!core_adfs_is_present) audit(AUDIT_NOT_INST, "ADFS 3.0");
}

vuln = 0;

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

port = kb_smb_transport();
login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

if(! smb_session_init()) audit(AUDIT_FN_FAIL, 'smb_session_init');

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

key = "SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\ApplicabilityEvaluationCache\Package_for_KB3134222~31bf3856ad364e35~amd64~~6.3.1.2";

files = list_dir(basedir:winsxs, level:0, dir_pat:"msil_microsoft.identityserver_31bf3856ad364e35_", file_pat:"^MicroSoft\.IdentityServer\.dll$", max_recurse:1);

vuln += hotfix_check_winsxs(os:'6.3',
                            sp:0,
                            files:files,
                            versions:make_list('6.3.9600.18192'),
                            max_versions:make_list('6.3.9600.99999'),
                            bulletin:bulletin,
                            kb:kb,
                            key:key);

# cleanup
NetUseDel();

if (vuln)
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
