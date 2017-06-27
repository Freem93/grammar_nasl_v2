#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(16206);
 script_version("$Revision: 1.20 $");
 script_cvs_date("$Date: 2015/01/13 20:37:05 $");

 script_cve_id("CVE-2004-1061");
 script_bugtraq_id(12154);
 script_osvdb_id(12699);

 script_name(english:"Bugzilla Internal Error Response XSS");
 script_summary(english:"Checks Bugzilla version number");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI that is vulnerable to a cross-
site scripting attack.");
 script_set_attribute(attribute:"description", value:
"The remote host runs Bugzilla, a web-based bug tracking system.

The remote Bugzilla installation, according to its version number, is
vulnerable to a cross-site scripting attack when rendering internal
errors containing user-supplied input.");
 script_set_attribute(attribute:"solution", value:"Upgrade to Bugzilla 2.18.0 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/01");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/19");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:bugzilla");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");

 script_dependencies("bugzilla_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 script_require_keys("installed_sw/Bugzilla", "Settings/ParanoidReport");

 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

app = 'Bugzilla';
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80);

# Check the installed version.
install = get_single_install(
  app_name : app,
  port     : port,
  exit_if_unknown_ver : TRUE
);

version = install['version'];
dir = install['path'];
install_loc = build_url(port:port, qs:dir+'/query.cgi');

if(ereg(pattern:"^(1\..*)|(2\.(0\..*|1[0-7]\..*))", string:version))
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report =
      '\n  Version : ' + version +
      '\n  URL     : ' + install_loc;
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_loc, version);
