#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59055);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/02/03 17:40:02 $");

  script_cve_id(
    "CVE-2012-2003",
    "CVE-2012-2004",
    "CVE-2012-2005",
    "CVE-2012-2006"
  );
  script_bugtraq_id(53341);
  script_osvdb_id(81666, 81667, 81668, 81669);

  script_name(english:"HP Insight Management Agents Multiple Vulnerabilities");
  script_summary(english:"Checks file version");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The management agent installed on the remote Windows host has multiple
vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"According to its version, the installation of HP Insight Management
Agents on the remote host has multiple unspecified vulnerabilities,
including cross-site scripting, cross-site request forgery, denial of
service, and unauthorized modification."
  );
  # http://h20000.www2.hp.com/bizsupport/TechSupport/Document.jsp?objectID=c03301267
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?7efecd6b");
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to HP Insight Management Agents 9.0.0.0 or later."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/05/09");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:insight_management_agents");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");

  script_dependencies("smb_hotfixes.nasl", "smb_enum_services.nasl");
  script_require_ports(139, 445);

  exit(0);
}

include("smb_func.inc");
include("smb_hotfixes.inc");
include("smb_hotfixes_fcheck.inc");
include("smb_reg_query.inc");
include("misc_func.inc");
include("audit.inc");

# Covers the three services installed by HP Insight Management Agents installer: CqMgHost, CqMgServ, CqMgStor
get_kb_list_or_exit('SMB/svc/CqMg*');

if (!is_accessible_share())
  audit(AUDIT_FN_FAIL, 'is_accessible_share');

path = hotfix_get_systemroot() + "\system32\CpqMgmt\agentver.dll";
ver = hotfix_get_fversion(path:path);
hotfix_check_fversion_end();

if (ver['error'] != HCF_OK)
  audit(AUDIT_VER_FAIL, path);
else
  ver = ver['value'];

ver = join(ver, sep:'.');
fix = '9.0.0.0';

if (ver_compare(ver:ver, fix:fix) >= 0)
  audit(AUDIT_INST_VER_NOT_VULN, 'HP Insight Management Agents', ver);

port = kb_smb_transport();
set_kb_item(name:'www/0/XSRF', value:TRUE);
set_kb_item(name:'www/0/XSS', value:TRUE);

if (report_verbosity > 0)
{
  report =
    '\n  Path              : ' + path +
    '\n  Installed version : ' + ver +
    '\n  Fixed Version     : ' + fix + '\n';
  security_warning(port:port, extra:report);
}
else security_warning(port);
