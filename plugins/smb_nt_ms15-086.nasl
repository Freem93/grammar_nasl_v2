#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85346);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/01/28 22:37:18 $");

  script_cve_id("CVE-2015-2420");
  script_bugtraq_id(76258);
  script_osvdb_id(125994);
  script_xref(name:"MSFT", value:"MS15-086");
  script_xref(name:"IAVA", value:"2015-A-0191");

  script_name(english:"MS15-086: Vulnerability in System Center Operations Manager Could Allow Elevation of Privilege (3075158)");
  script_summary(english:"Checks the version of Web Console-specific DLL.");

  script_set_attribute(attribute:"synopsis", value:
"A web application hosted on the remote Windows system is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Microsoft System Center Operations Manager installed on
the remote Windows host is affected by a cross-site scripting
vulnerability in the Web Console component due to improper validation
of user-supplied input. An attacker can exploit this vulnerability by
convincing a user to request a specially crafted URL, resulting in
arbitrary script code execution.");
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms15-086");
  script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for System Center Operations
Manager 2012 and 2012 R2.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("system_center_operations_mgr_installed.nasl", "ms_bulletin_checks_possible.nasl");
  script_require_keys("SMB/MS_Bulletin_Checks/Possible");
  script_require_ports(139, 445, "Host/patch_management_checks");

  exit(0);
}

include("audit.inc");
include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("misc_func.inc");

get_kb_item_or_exit('SMB/MS_Bulletin_Checks/Possible');

bulletin = 'MS15-086';
kbs = make_list('3071088', '3071089', '3064919');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

# not sure if you can have multiple versions installed on the same system, but this code assumes that you can
paths = get_kb_list('SMB/System Center Operations Manager/Install/*');

if (isnull(paths))
   audit(AUDIT_NOT_INST, "Microsoft System Center Operations Manager");

failed_shares = make_list();
vulns = 0;
connection_made = FALSE;

foreach path (make_list(paths))
{
  share = path[0] + '$';

  if (!is_accessible_share(share:share))
  {
    failed_shares = list_uniq(make_list(failed_shares, share));
    continue;
  }

  path -= "Server\";
  path += "WebConsole\WebHost\bin";
  file = 'Microsoft.EnterpriseManagement.Presentation.WebConsole.dll';

  # KB3071089
  # Microsoft System Center 2012 Operations Manager
  # (Installs Update Rollup 8)
  vulns += hotfix_is_vulnerable(path:path, file:file, min_version:'7.0.8560.0', version:'7.0.8560.1048', bulletin:bulletin, kb:'3071089');

  # KB3071088
  # Microsoft System Center 2012 Operations Manager Service Pack 1
  # (Installs Update Rollup 10)
  vulns += hotfix_is_vulnerable(path:path, file:file, min_version:'7.0.9538.0', version:'7.0.9538.1136', bulletin:bulletin, kb:'3071088');

  # KB3064919
  # Microsoft System Center 2012 Operations Manager R2
  # (Installs Update Rollup 7)
  vulns += hotfix_is_vulnerable(path:path, file:file, min_version:'7.1.10226.0', version:'7.1.10226.1090', bulletin:bulletin, kb:'3064919');

  connection_made = TRUE;
}

if (connection_made)
  hotfix_check_fversion_end();

if (vulns == 0)
{
  # the plugin will only alert on connection errors if no vulnerabilities were detected.
  # if some connections failed but some vulnerabilities were detected, partial results are reported
  if (max_index(failed_shares) > 0)
  {
    shares = join(failed_shares, ', ');
    audit(AUDIT_SHARE_FAIL, shares);
  }
  else
  {
    audit(AUDIT_HOST_NOT, 'affected');
  }
}

# report results
set_kb_item(name:'SMB/Missing/'+bulletin, value:TRUE);
set_kb_item(name:'www/0/XSS', value:TRUE);
hotfix_security_warning();
