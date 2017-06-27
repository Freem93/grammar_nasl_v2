#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(42338);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/12 14:46:30 $");

  script_cve_id("CVE-2009-3441");
  script_bugtraq_id(36504);
  script_osvdb_id(58374);
  script_xref(name:"Secunia", value:"36867");

  script_name(english:"OSSIM 'host/draw_tree.php' Access Restriction Weakness Information Disclosure");
  script_summary(english:"Tries to access a page that should require authentication");

  script_set_attribute(attribute:"synopsis", value:
"An application running on the remote web server has an unauthorized
access vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of OSSIM running on the remote host has an unauthorized
access vulnerability. It is possible to access the
'host/draw_tree.php' page without providing authentication. This page
includes information about the network's topology. A remote attacker
could use this information to mount further attacks.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/506663");
  # http://web.archive.org/web/20101224083941/https://www.alienvault.com/community.php?section=News#92
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9fa7cc84");
  script_set_attribute(attribute:"solution", value:"Upgrade to OSSIM version 2.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("ossim_web_detect.nasl");
  script_require_keys("www/ossim", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");


port = get_http_port(default:80, php:TRUE);

install = get_install_from_kb(appname:'ossim', port:port);
if (isnull(install)) exit(0, "OSSIM wasn't detected on port "+port+".");

url = string(install['dir'], '/host/draw_tree.php');
res = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(res)) exit(1, "The web server on port "+port+" failed to respond.");

hdrs = parse_http_headers(status_line:res[0], headers:res[1]);
if (isnull(hdrs['$code'])) code = 0;
else code = hdrs['$code'];

if (code == 200 && 'pixmaps/theme/host.png' >< res[2])
{
  if (report_verbosity > 0)
  {
    report = get_vuln_report(
      header:"Nessus was able verify the issue using the following URL",
      items:url,
      port:port
    );

    security_warning(port:port, extra:report);
  }
  else security_warning(port);
}
else exit(0, "The OSSIM install at "+build_url(port:port, qs:url)+" is not affected.");
