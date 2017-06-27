#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(73272);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2014-2314");
  script_bugtraq_id(65849);
  script_osvdb_id(103807);
  script_xref(name:"EDB-ID", value:"32725");

  script_name(english:"Atlassian JIRA < 6.0.4 Arbitrary File Creation");
  script_summary(english:"Checks the version of JIRA.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a web application that is potentially
affected by an arbitrary file creation vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the version of
Atlassian JIRA hosted on the remote web server is prior to version
6.0.4. It is, therefore, potentially affected by an arbitrary file
creation vulnerability due to a flaw in the Issue Collector plugin in
which the 'filename' POST parameter is not properly sanitized, which
allows traversing outside a restricted path. A remote, unauthenticated
attacker, using a crafted request, can exploit this vulnerability to
create files in arbitrary directories in the JIRA installation.

This vulnerability only affects JIRA installations running on the
Windows OS.

Note that the Issue Collector plugin for JIRA is also affected by this
vulnerability; however, Nessus did not did confirm that this plugin is
installed.");
  # https://confluence.atlassian.com/display/JIRA/JIRA+Security+Advisory+2014-02-26
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?df77438c");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/JRA-36442");
  script_set_attribute(attribute:"solution", value:
"Upgrade to JIRA 6.0.4 or later, and upgrade or disable the Issue
Collector plugin.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'JIRA Issues Collector Directory Traversal');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/02/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/31");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:jira");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("jira_detect.nasl");
  script_require_keys("installed_sw/Atlassian JIRA", "Settings/ParanoidReport");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("http.inc");
include("misc_func.inc");
include("install_func.inc");

app = "Atlassian JIRA";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:8080);

install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

# Prevent potential false positives.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

dir = install['path'];
ver = install['version'];

url = build_url(port:port, qs:dir);

# Check if the host is affected.
fix = "6.0.4";
if (ver_compare(ver:ver, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_WEB_APP_NOT_AFFECTED, app, url, ver);

# Report our findings.
report = NULL;
if (report_verbosity > 0)
{
  report =
    '\n  URL               : ' + url +
    '\n  Installed version : ' + ver +
    '\n  Fixed version     : ' + fix +
    '\n';
}

security_warning(port:port, extra:report);
