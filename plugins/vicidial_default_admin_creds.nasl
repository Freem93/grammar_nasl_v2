#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(38890);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/09/24 23:21:22 $");

  script_name(english:"VICIDIAL Call Center Suite Default Administrative Credentials");
  script_summary(english:"Tries to login with default credentials");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web application is protected using default credentials."
  );
  script_set_attribute(  attribute:"description",   value:
"The remote host is running the VICIDIAL Call Center Suite, a set of
programs for Asterisk that act as a complete call center suite.

The remote installation of VICIDIAL is configured to use default
credentials to control administrative access.  Knowing these, an
attacker can gain administrative control of the affected application."  );
  script_set_attribute(  attribute:"solution",   value:
"Change the password for the admin user."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/26");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"default_account", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning", "global_settings/supplied_logins_only");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0, php:TRUE);
if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);


user = "6666";
pass = "1234";


# Loop through directories.
#
# nb: I don't expect the directory will be discovered generally.
dirs = list_uniq(make_list("/vicidial", cgi_dirs()));

foreach dir (dirs)
{
  # Try to exploit the issue to bypass authentication.
  url = dir + "/admin.php";

  req = http_mk_get_req(
    port        : port,
    item        : url, 
    add_headers : make_array(
      'Authorization',
      ('Basic ' + base64(str:user+":"+pass))
    )
  );
  res = http_send_recv_req(port:port, req:req);
  if (isnull(res)) exit(0);
  install_url = build_url(qs:dir, port:port);

  # There's a problem if we've bypassed authentication.
  if (
    'title>VICIDIAL ADMIN:' >< res[2] &&
    '/admin.php?force_logout=1">' >< res[2]
  )
  {
    if (report_verbosity > 0)
    {
      report =
        '\n' +
        'Nessus was able to gain access using the following information :\n' +
        '\n' +
        '  URL      : ' + install_url + '/admin.php' +
        '  User     : ' + user + '\n' +
        '  Password : ' + pass + '\n';
      security_hole(port:port, extra:report);
    }
    else security_hole(port);
    exit(0);
  }
}
audit(AUDIT_HOST_NOT, 'affected');
