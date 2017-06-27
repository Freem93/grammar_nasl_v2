#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46199);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/01/13 20:37:05 $");

  script_bugtraq_id(39679);
  script_xref(name:"Secunia", value:"39547");

  script_name(english:"Ektron CMS400.NET 'workarea/reterror.aspx' info Parameter XSS");
  script_summary(english:"Tries to inject script code through 'info' parameter");

  script_set_attribute(attribute:"synopsis",value:
"The remote web server hosts an application that is prone to a cross-
site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The installed version of Ektron CMS400.NET fails to sanitize user-
supplied input to the 'info' parameter in the 'workarea/reterror.aspx'
script before using it to generate dynamic HTML content.

An unauthenticated, remote attacker may be able to leverage this issue
to inject arbitrary HTML or script code into a user's browser to be
executed within the security context of the affected site.");

  script_set_attribute(attribute:"see_also", value:"http://www.westpoint.ltd.uk/advisories/wp-09-0005.txt");
  script_set_attribute(attribute:"see_also", value:"http://dev.ektron.com/forum.aspx?g=posts&t=31005");
  script_set_attribute(attribute:"see_also", value:"http://dev.ektron.com/cms400releasenotes.aspx#766sp5");

  script_set_attribute(attribute:"solution", value:"Upgrade to Ektron CMS400.NET 7.66 SP5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"vuln_publication_date", value:"2009/10/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");  
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/30");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");

  script_dependencies("ektron_cms400_detect.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/cms400","www/ASP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80, asp:TRUE);

install = get_install_from_kb(appname:'cms400', port:port, exit_on_fail:TRUE);
dir = install['dir'];

# Try to exploit the issue.
exploit = '<script>alert(' + "'" + SCRIPT_NAME + "'" + ')</script>';

vuln = test_cgi_xss(
  port     : port,
  cgi      : "/WorkArea/reterror.aspx",
  dirs     : make_list(dir),
  qs       : "info="+exploit,
  pass_str : 'class="exception">'+exploit,
  pass_re  : "The following error has occurred:"
);

if (!vuln)
{
  install_url = build_url(qs:install['dir'] + '/', port:port);
  exit(0, "The Ektron CMS400.NET install at " + install_url + " is not affected.");
}
