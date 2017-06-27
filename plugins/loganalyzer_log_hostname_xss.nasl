#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79743);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/20 14:03:01 $");

  script_cve_id("CVE-2014-6070");
  script_bugtraq_id(69539);
  script_osvdb_id(110685, 110689);
  script_xref(name:"EDB-ID", value:"34525");

  script_name(english:"LogAnalyzer < 3.6.6 index.php / detail.php 'hostname' Parameter XSS");
  script_summary(english:"Checks the version of LogAnalyzer.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts a PHP script that is affected by a
cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The LogAnalyzer install hosted on the remote web server is affected by
a cross-site scripting vulnerability due to a failure to properly
sanitize the 'hostname' value retrieved from log files. An attacker
can exploit this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site. The attacker must be able to manipulate log files
analyzed by the application in order to exploit this flaw.");
  # http://loganalyzer.adiscon.com/downloads/loganalyzer-3-6-6-v3-stable/
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b2dcb117");
  script_set_attribute(attribute:"solution", value:"Upgrade to version 3.6.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/12/05");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:adiscon:loganalyzer");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");

  script_dependencies("loganalyzer_detect.nasl");
  script_require_keys("installed_sw/Adiscon LogAnalyzer");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

appname = "Adiscon LogAnalyzer";
get_install_count(app_name:appname, exit_if_zero:TRUE);

port    = get_http_port(default:80, php:TRUE);
install = get_single_install(app_name:appname, port:port, exit_if_unknown_ver:TRUE);
version = install["version"];
url     = build_url(qs:install["path"]+"/", port:port);

if (ver_compare(ver:version, fix:"3.6.6", strict:FALSE) < 0)
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' + url +
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 3.6.6' +
      '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, url, version);
