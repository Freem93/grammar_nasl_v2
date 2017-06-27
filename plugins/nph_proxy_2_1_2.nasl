#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(58833);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2012/04/24 10:51:08 $");

  script_bugtraq_id(52994);
  script_osvdb_id(81031);
  
  script_name(english:"CGIProxy < 2.1.2 Multiple Unspecified Vulnerabilities");
  script_summary(english:"Checks version of CGIProxy");

  script_set_attribute(
    attribute:"synopsis",
    value:
"The remote web server hosts a web application that is affected by
multiple vulnerabilities."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of CGIProxy hosted on the remote web server is less than
2.1.2.  As such, it is reportedly affected by multiple unspecified
vulnerabilities."
  );
  script_set_attribute(attribute:"see_also", value:"http://www.jmarshall.com/tools/cgiproxy/CHANGES.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to CGIProxy 2.1.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2012/04/08");
  script_set_attribute(attribute:"patch_publication_date", value:"2012/04/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:jmarshall:cgiproxy");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("nph_proxy_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/nph_proxy");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
include("webapp_func.inc");
include("audit.inc");

port = get_http_port(default:80);

install = get_install_from_kb(
  appname : 'nph_proxy', 
  port    : port, 
  exit_on_fail:TRUE
);

dir = install['dir'];
install_url = build_url(port:port,qs:dir + "/nph-proxy.cgi");
version = install['ver'];
if (version == UNKNOWN_VER) exit(1, "The version of CGIProxy at "+install_url+" could not be determined.");

if (ver_compare(ver:version, fix:'2.1.2', strict:FALSE) == -1)
{
  if (report_verbosity > 0)
  {
    report = 
      '\n  URL               : ' + install_url + 
      '\n  Installed version : ' + version +
      '\n  Fixed version     : 2.1.2' +
      '\n'; 
    security_hole(port:port, extra:report);  
  }
  else security_hole(port);
  exit(0);
}
else audit(AUDIT_INST_VER_NOT_VULN, "CGIProxy", version);
