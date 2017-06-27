#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63421);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/04/23 21:44:06 $");

  script_cve_id("CVE-2013-0009", "CVE-2013-0010");
  script_bugtraq_id(55401, 55408);
  script_osvdb_id(88960, 88961, 92931);
  script_xref(name:"IAVB", value:"2013-B-0002");
  script_xref(name:"MSFT", value:"MS13-003");

  script_name(english:"MS13-003: Vulnerabilities in System Center Operations Manager Could Allow Elevation of Privilege (2748552)");
  script_summary(english:"Checks version of Web Console-specific DLL");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web application hosted on the remote Windows system has multiple
cross-site scripting vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of System Center Operations Manager installed on the remote
host has multiple reflected cross-site scripting vulnerabilities in the
Web Console component.  An attacker could exploit this by tricking a
user into requesting a specially crafted URL, resulting in arbitrary
script code execution."
  );
  script_set_attribute(attribute:"see_also", value:"https://technet.microsoft.com/library/security/ms13-003");
  script_set_attribute(
    attribute:"solution",
    value:
"Microsoft has released a set of patches for System Center Operations
Manager 2007 and 2007 R2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:microsoft:windows");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:system_center_operations_manager");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows : Microsoft Bulletins");

  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");

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

bulletin = 'MS13-003';
kbs = make_list('2783850', '2809182');

if (get_kb_item('Host/patch_management_checks')) hotfix_check_3rd_party(bulletin:bulletin, kbs:kbs, severity:SECURITY_WARNING);

# not sure if you can have multiple versions installed on the same system, but this code assumes that you can
paths = get_kb_list_or_exit('SMB/System Center Operations Manager/Install/*', exit_code:0);
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

  # this function returns 0 for not vulnerable, 1 for vulnerable
  path += "\Web Console\bin";
  file = 'Microsoft.EnterpriseManagement.OperationsManager.Web.ConsoleFramework.dll';

  # SCOM 2007 SP1
  vulns += hotfix_is_vulnerable(path:path, file:file, min_version:'6.0.6278.0', version:'6.0.6278.124', bulletin:bulletin, kb:'2809182');
  # SCOM 2007 R2
  vulns += hotfix_is_vulnerable(path:path, file:file, min_version:'6.1.7221.0', version:'6.1.7221.110', bulletin:bulletin, kb:'2783850');
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
