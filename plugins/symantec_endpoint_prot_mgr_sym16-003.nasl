#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90200);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/07/11 13:15:59 $");

  script_cve_id(
    "CVE-2015-8152",
    "CVE-2015-8153"
  );
  script_bugtraq_id(
    84343,
    84354
  );
  script_osvdb_id(
    136013,
    136012
  );

  script_name(english:"Symantec Endpoint Protection Manager < 12.1 RU6 MP4 Multiple Vulnerabilities (SYM16-003)");
  script_summary(english:"Checks the SEPM version.");

  script_set_attribute(attribute:"synopsis", value:
"The version of Symantec Endpoint Protection Manager installed on the
remote host is affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Symantec Endpoint Protection Manager (SEPM) installed
on the remote host is prior to 12.1 RU6 MP4. It is, therefore,
affected by the following vulnerabilities :

  - A cross-site request forgery (XSRF) vulnerability exists
    due to HTTP requests to logging scripts not requiring
    multiple steps, explicit confirmation, or a unique token
    when performing certain sensitive actions. A remote
    attacker can exploit this by convincing a user to follow
    a specially crafted link, resulting in the execution of
    arbitrary code. (CVE-2015-8152)

  - A SQL injection vulnerability exists due to improper
    sanitization of input before using it in SQL queries. An
    authenticated, remote attacker can exploit this to
    inject or manipulate SQL queries on the back-end
    database, resulting in the manipulation and disclosure
    of arbitrary data. (CVE-2015-8153)");
  # https://www.symantec.com/security_response/securityupdates/detail.jsp?fid=security_advisory&pvid=security_advisory&year=&suid=20160317_00
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e94f36bc");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Symantec Endpoint Protection Manager 12.1 RU6 MP4 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/25");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:symantec:endpoint_protection_manager");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("symantec_endpoint_prot_mgr_installed.nasl");
  script_require_keys("installed_sw/Symantec Endpoint Protection Manager");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app = 'Symantec Endpoint Protection Manager';

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);

version = install['version'];
path    = install['path'   ];

fixed_ver = '12.1.6860.6400';

if (version =~ "^12\.1\." && ver_compare(ver:version, fix:fixed_ver, strict:FALSE) == -1)
{
  port = get_kb_item("SMB/transport");
  if (!port) port = 445;

  report =
    '\n  Path              : '+ path +
    '\n  Installed version : '+ version +
    '\n  Fixed version     : '+ fixed_ver +
    '\n';
  security_report_v4(severity:SECURITY_HOLE, port:port, extra:report, sqli:TRUE, xsrf:TRUE);
}
else audit(AUDIT_INST_PATH_NOT_VULN, app, version, path);
