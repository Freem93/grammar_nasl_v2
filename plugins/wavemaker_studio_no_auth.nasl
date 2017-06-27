#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60062);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2012/07/19 19:27:21 $");

  script_name(english:"WaveMaker Studio Requires No Authentication");
  script_summary(english:"Checks KB to see if authentication is required");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A web development application hosted on the remote web server does not
require authentication."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The version of WaveMaker Studio detected on the remote host does not
require authentication.  A remote, unauthenticated attacker could
exploit this to create, modify, and deploy projects."
  );
  script_set_attribute(attribute:"see_also", value:"http://dev.wavemaker.com/forums/?q=node/2304");
  script_set_attribute(attribute:"see_also", value:"http://dev.wavemaker.com/forums/?q=node/8418");
  script_set_attribute(
    attribute:"solution",
    value:
"Configure WaveMaker Studio to require authentication using one of the
methods in the referenced WaveMaker forum posts."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/19");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/a:vmware:wavemaker");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2012 Tenable Network Security, Inc.");

  script_dependencies("wavemaker_studio_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/wavemaker_studio");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:8094);
get_kb_item_or_exit('www/' + port + '/wavemaker_studio/noauth');
install = get_install_from_kb(appname:'wavemaker_studio', port:port, exit_on_fail:TRUE);

if (report_verbosity > 0)
{
  header = 'The following WaveMaker Studio install does not require authentication';
  report = get_vuln_report(header:header, port:port, items:install['dir'] + '/');
  security_hole(port:port, extra:report);
}
else security_hole(port);
