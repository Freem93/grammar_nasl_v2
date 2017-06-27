#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(71846);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/03/25 13:32:30 $");

  script_cve_id("CVE-2013-6397");
  script_bugtraq_id(63935);
  script_osvdb_id(100374);

  script_name(english:"Apache Solr < 4.6.0 'SolrResourceLoader' Directory Traversal");
  script_summary(english:"Checks version of Solr");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
a directory traversal vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of Apache Solr running on the remote web server is
affected by a directory traversal vulnerability because the
'SolrResourceLoader' class fails to restrict access to the loading of
specially crafted XLS stylesheets and velocity templates. A remote,
unauthenticated attacker can exploit this issue by crafting a URL with
directory traversal characters to access resources outside of the
instance directory.");
  # http://www.agarri.fr/kom/archives/2013/11/27/compromising_an_unreachable_solr_server_with_cve-2013-6397/index.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?80d8fbac");
  script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/SOLR-4882");
  script_set_attribute(attribute:"see_also", value:"http://lucene.apache.org/solr/4_6_0/changes/Changes.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Solr version 4.6.0 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/05/30");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:solr");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");

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

if (ver_compare(ver:version,fix:"4.6.0",strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report =
      '\n  URL               : ' +install_url+
      '\n  Installed version : ' +version+
      '\n  Fixed version     : 4.6.0\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, appname, install_url, version);
