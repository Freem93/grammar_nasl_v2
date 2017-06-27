#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99986);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2017/05/05 12:16:31 $");

  script_cve_id("CVE-2017-7415");
  script_bugtraq_id(97961);
  script_osvdb_id(156026);
  script_xref(name:"IAVA", value:"2017-A-0130");

  script_name(english:"Atlassian Confluence 6.0.x < 6.0.7 Drafts diff REST Information Disclosure");
  script_summary(english:"Checks the Atlassian Confluence version.");

  script_set_attribute(attribute:"synopsis", value:
"A web application running on the remote host is affected by an
information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"According to its self-reported version number, the Atlassian
Confluence application running on the remote host is 6.0.x prior to
6.0.7. It is, therefore, affected by an information disclosure
vulnerability in the Confluence drafts diff REST resource due to
making available the page IDs or draft IDs without requiring
authentication. A remote attacker with access to the Confluence web
interface can exploit this, by enumerating the IDs, to disclose the
potentially sensitive contents of all blogs and pages in Confluence.
Furthermore, if anonymous access has been enabled, a valid user
account is not required to exploit this vulnerability.

Note that Nessus has not tested for this issue but has instead relied
only on the application's self-reported version number.");
  # https://confluence.atlassian.com/doc/confluence-security-advisory-2017-04-19-887071137.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?21bcd1e2");
  script_set_attribute(attribute:"see_also", value:"https://jira.atlassian.com/browse/CONFSERVER-52222");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Atlassian Confluence version 6.0.7 or later, or apply the
appropriate vendor patch.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N");

  script_set_attribute(attribute:"vuln_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:atlassian:confluence");
  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"stig_severity", value:"II");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");

  script_dependencies("confluence_detect.nasl");
  script_require_ports("Services/www", 8080, 8090);
  script_require_keys("www/confluence", "Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8090);

install = get_install_from_kb(
  appname      :'confluence',
  port         :port,
  exit_on_fail :TRUE
);

dir     = install['dir'];
version = install['ver'];
install_url = build_url(port:port, qs:dir);
fix_ver = '6.0.7';

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, "Confluence", install_url);
if (report_paranoia < 2) audit(AUDIT_PARANOID);
if (version =~ '^6(\\.0)?$') audit(AUDIT_VER_NOT_GRANULAR, "Confluence", port, version);

# Affects versions < 6.0.7
if (ver_compare(ver:version, minver:"6.0.0", fix:fix_ver, strict:FALSE) == -1)
{
  report =
    '\n  URL               : ' + install_url +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix_ver + 
    '\n';
  security_report_v4(severity:SECURITY_WARNING, port:port, extra:report);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, "Confluence", install_url, version);
