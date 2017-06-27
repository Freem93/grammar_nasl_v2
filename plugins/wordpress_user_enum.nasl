#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90067);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/03/21 20:47:13 $");

  script_name(english:"WordPress User Enumeration");
  script_summary(english:"Attempts to enumerate WordPress users.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress hosted on the remote web server is affected
by a user enumeration vulnerability. An unauthenticated, remote
attacker can exploit this to learn the names of valid WordPress users.
This information could be used to mount further attacks.");
  script_set_attribute(attribute:"see_also", value:"https://hackertarget.com/wordpress-user-enumeration/");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("install_func.inc");

app = "WordPress";
get_install_count(app_name:app, exit_if_zero:TRUE);

port = get_http_port(default:80, php:TRUE);

install = get_single_install(
  app_name : app,
  port     : port
);

path = install['path']; # e.g. /blog
install_url = build_url(port:port, qs:path);

if (thorough_tests) max = 10;
else max = 3;

user_regex = "[a-z0-9A-Z-.]+"; # match a username

header_patterns = make_list(
  'Location:.*/author/(' + user_regex +')/'
);
body_patterns = make_list(
  '<body class=\".*author\\sauthor-(' + user_regex + ').*\">',
  'title=\"View all posts by (' + user_regex +')\">'
);

base_uri = path + '/?author=';  # e.g. /blog/?author=

users = make_list();
for (i = 1; i <= max; i++)
{
  found = FALSE;
  uri = base_uri + i;

  res = http_send_recv3(
    method          : "GET",
    item            : uri,
    port            : port,
    follow_redirect : 3,
    fetch404        : TRUE,
    exit_on_fail    : TRUE
  );

  # search response headers
  foreach p (header_patterns)
  {
    match = eregmatch(pattern:p, string:res[1]);
    if (!isnull(match) && !isnull(match[1]))
    {
      users = make_list(users, match[1]); # user found
      found = TRUE;
      break;
    }
  }

  if (!found)
  {
    # search response body
    foreach p (body_patterns)
    {
      match = eregmatch(pattern:p, string:res[2]);
      if (!isnull(match) && !isnull(match[1]))
      {
        users = make_list(users, match[1]); # user found
        break;
      }
    }
  }
}

if (!empty_or_null(users))
{
  report = 'Nessus was able to enumerate the following ' + app +
           " users from the " + app + " install at '" + install_url +
           "' :";
  foreach user (list_uniq(users))
  {
    report += '\n ' + user;
  }

  security_report_v4(port:port, extra:report, severity:SECURITY_WARNING);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
