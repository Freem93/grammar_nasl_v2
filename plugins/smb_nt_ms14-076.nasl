#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79135);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2014/12/23 21:34:38 $");

  script_cve_id("CVE-2014-4078");
  script_bugtraq_id(70937);
  script_osvdb_id(114534);
  script_xref(name:"MSFT", value:"MS14-076");
  script_xref(name:"IAVB", value:"2014-B-0146");

  script_name(english:"MS14-076: Vulnerability in Internet Information Services (IIS) Could Allow Security Feature Bypass (2982998)");
  script_summary(english:"Checks the version of diprestr.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by a security feature bypass
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by a security feature bypass
vulnerability that can lead to a bypass of the 'IP Address and Domain
Restrictions' filtering rules. Successful exploitation of this
vulnerability by a remote attacker allows clients from restricted or
blocked domains to gain access to restricted web resources.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms14-076");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 8, 2012, 8.1, and
2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

global_var bulletin, vuln;

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');
bulletin = 'MS14-076';

kb = 2982998;
kbs = make_list(kb);

if (get_kb_item("Host/patch_management_checks")) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

if (hotfix_check_sp_range(win8:'0', win81:'0') <= 0) audit(AUDIT_OS_SP_NOT_VULN);

get_kb_item_or_exit("SMB/Registry/Enumerated", exit_code:1);
vuln = 0;

systemroot = hotfix_get_systemroot();
if (!systemroot) audit(AUDIT_PATH_NOT_DETERMINED, 'system root');

# Check for registry key to see if this update was installed
# and then uninstalled at some point in time. The dll versions
# may not be properly updated upon uninstalling the update.
# The 'uninstalled' variable is used later if necessary.
# Also, check that the IPSecurity subcomponent is enabled. This
# update is not offered without it.
registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
uninstalled = get_reg_name_value_table(handle:hklm ,key:"SOFTWARE\Microsoft\Windows\CurrentVersion\Component Based Servicing\CatalogsToUninstall");
subcomponent = get_registry_value(handle:hklm, item:"SOFTWARE\Microsoft\InetStp\Components\IPSecurity");
RegCloseKey(handle:hklm);
close_registry();

# Determine if IPSecurity subcomponent is enabled
# Note that the reg key is the same for both Windows 8
# and Server 2012 despite the features being named
# differently.
if (empty_or_null(subcomponent)) audit(AUDIT_HOST_NOT, "affected");

port = kb_smb_transport();
name = kb_smb_name();
soc  = open_sock_tcp(port);

if (!soc) audit(AUDIT_SOCK_FAIL, port);

session_init(socket:soc, hostname:name);

login  = kb_smb_login();
pass   = kb_smb_password();
domain = kb_smb_domain();

winsxs = ereg_replace(pattern:'^[A-Za-z]:(.*)', replace:"\1\WinSxS", string:systemroot);
winsxs_share = hotfix_path2share(path:systemroot);

rc = NetUseAdd(login:login, password:pass, domain:domain, share:winsxs_share);
if (rc != 1)
{
  NetUseDel();
  audit(AUDIT_SHARE_FAIL, winsxs_share);
}

##############
# diprestr.dll
##############
files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft-windows-iis-ipsecuritybinaries", file_pat:"^iprestr\.dll$", max_recurse:1);

# Windows 8 / 2012
vuln += hotfix_check_winsxs(os:'6.2',
                            sp:0,
                            files:files,
                            versions:make_list('8.0.9200.17101', '8.0.9200.21218'),
                            max_versions:make_list('8.0.9200.20000', '8.0.9200.99999'),
                            bulletin:bulletin,
                            kb:kb);

## Leaving the following check out pending
## further review
# Windows 8.1 / 2012 R2
#files = NULL;
#files = list_dir(basedir:winsxs, level:0, dir_pat:"microsoft-windows-iis-ipsecuritybinaries", file_pat:"^diprestr\.dll$", max_recurse:1);
#
#vuln += hotfix_check_winsxs(os:'6.3',
#                            sp:0,
#                            files:files,
#                            versions:make_list('8.5.9600.16384'),
#                            max_versions:make_list('8.5.9600.20000'),
#                            bulletin:bulletin,
#                            kb:kb);

# cleanup
NetUseDel();

if (vuln)
{
  set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
  hotfix_security_warning();
  hotfix_check_fversion_end();
  exit(0);
}
else
{
  hotfix_check_fversion_end();

  # Use our check from earlier to decide if the patch was uninstalled or not
  foreach entry (uninstalled)
  {
    if ("KB2982998" >< entry)
      exit(0, "The update associated with KB2982998 appears to have been uninstalled.");
  }
  audit(AUDIT_HOST_NOT, 'affected');
}
