#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85406);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/08/17 13:58:23 $");

  script_cve_id("CVE-2015-2475");
  script_bugtraq_id(76259);
  script_osvdb_id(125995);
  script_xref(name:"MSFT", value:"MS15-087");
  script_xref(name:"IAVB", value:"2015-B-0097");

  script_name(english:"MS15-087: Vulnerability in UDDI Services Could Allow Elevation of Privilege (3082459)");
  script_summary(english:"Checks the version of the UDDI service.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host is affected by an elevation of privilege
vulnerability in the Universal Description, Discovery, and Integration
(UDDI) Services component due to improper validation and sanitization
of user-supplied input to the 'searchID' parameter of the 'explorer'
frame in frames.aspx. A remote attacker can exploit this vulnerability
by submitting a specially crafted URL to a target site, resulting in
the execution of arbitrary script code in the context of the current
user.

Note: During testing it was discovered that BizTalk configurations
running on Windows versions not specified in the bulletin were also
impacted. Therefore, this plugin checks the vulnerability state of the
cross-site scripting flaw and not the specific OS variant.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/MS15-087");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for UDDI Services including
patches for Microsoft Windows 2008 SP2, BizTalk Server 2010, 2013, and
2013 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:biztalk_server");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "ms_bulletin_checks_possible.nasl", "wmi_enum_server_features.nbin");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_hotfixes.inc");
include("smb_func.inc");
include("smb_reg_query.inc");
include("misc_func.inc");

get_kb_item_or_exit("SMB/MS_Bulletin_Checks/Possible");

bulletin = 'MS15-087';
kbs = make_list("3073893", "3087119");

if (get_kb_item("Host/patch_management_checks"))
  hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

get_kb_item_or_exit("SMB/Registry/Enumerated");
productname = get_kb_item_or_exit("SMB/ProductName", exit_code:1);

share = hotfix_get_systemdrive(exit_on_fail:TRUE, as_share:TRUE);
if (!is_accessible_share(share:share)) audit(AUDIT_SHARE_FAIL, share);

registry_init();
hklm = registry_hive_connect(hive:HKEY_LOCAL_MACHINE, exit_on_fail:TRUE);
key = "SOFTWARE\Microsoft\UDDI\InstallRoot";

path = get_registry_value(handle:hklm, item:key);
RegCloseKey(handle:hklm);
if (isnull(path))
{
  close_registry();
  audit(AUDIT_NOT_INST, "UDDI Service");
}

file = hotfix_append_path(path:path, value:"\webroot\search\frames.aspx");
contents = hotfix_get_file_contents(file);
err_res = hotfix_handle_error(error_code:contents['error'], file:file, exit_on_fail:TRUE);
hotfix_check_fversion_end();

data = contents['data'];

if ("results.aspx?frames=true&search=<%=searchID%>" >< data)
{
  # Determine which KB to use
  kb = "3087119";
  if ("2008" >< productname && "R2" >!< productname && get_kb_item('WMI/server_feature/11'))
    kb = "3073893";

  set_kb_item(name:"SMB/Missing/"+bulletin, value:TRUE);
  set_kb_item(name:'www/0/XSS', value:TRUE);
  report = '\nThe relevant update does not appear to be installed. This was' +
           '\ndetermined by checking the contents of :\n' +
           '\n' + file + '\n';
  hotfix_add_report(bulletin:bulletin, kb:kb, report);
  hotfix_security_warning();
  exit(0);
}
else
  audit(AUDIT_HOST_NOT, 'affected');
