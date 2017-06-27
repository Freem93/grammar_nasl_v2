#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82028);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/03/25 13:32:30 $");

  script_cve_id("CVE-2014-3628");
  script_bugtraq_id(73129);
  script_osvdb_id(116599);

  script_name(english:"Apache Solr < 4.10.5 'plugin.js' XSS");
  script_summary(english:"Checks the version of Apache Solr.");

  script_set_attribute(attribute:"synopsis", value: 
"The remote web server contains a Java application that is affected by
a persistent cross-site scripting (XSS) vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is
affected by a persistent cross-site scripting vulnerability due to a
failure to sanitize query histories before returning them to the user
of the Solr administration panel. A remote, unauthenticated attacker
can exploit this issue to execute arbitrary JavaScript within the
context of a victim's browser, allowing the attacker to steal session
information, log key strokes, and perform other malicious attacks.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2015/q1/850");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/SOLR-6738");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 4.10.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/03/15");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");

  script_dependencies("solr_detect.nbin");
  script_require_keys("installed_sw/Apache Solr");
  script_require_ports("Services/www", 8983);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Apache Solr";
get_install_count(app_name:appname,exit_if_zero:TRUE);
port    = get_http_port(default:8983);
install = get_single_install(
  app_name:appname,
  port:port, 
  exit_if_unknown_ver:TRUE
);

dir         = install["path"];
version     = install["version"];
install_url = build_url(port:port, qs:dir);

if (version == UNKNOWN_VER) audit(AUDIT_UNKNOWN_WEB_APP_VER, appname, install_url);

# Everything before 4.10.5 in the 4.x branch
if (version =~ "^4\." && ver_compare(ver:version,fix:"4.10.5",strict:FALSE) == -1)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 4.10.5\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
