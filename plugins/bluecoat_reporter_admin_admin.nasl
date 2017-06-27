#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(34346);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2013/01/25 01:19:07 $");

  script_name(english: "Blue Coat Reporter Default Password (admin) for 'admin' Account");
  script_summary(english: "Tries to log into Blue Coat Reporter as admin/admin");
 
 script_set_attribute(attribute:"synopsis", value:
"The administrative password for the remote web service can be guessed." );
 script_set_attribute(attribute:"description", value:
"Nessus could gain administrative access to the Blue Coat Reporter
install on the remote host using 'admin' for both the username and
password." );
 script_set_attribute(attribute:"solution", value:
"Change the admin password." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/10/06");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl", "bluecoat_reporter.nasl");
  script_require_ports("Services/www", 8987);
  script_require_keys("www/BCReport");
  exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8987);

banner = get_http_banner(port: port);
if (! banner ||
    ! egrep(string: banner, pattern: '^Server:[ \t]*BCReport/')) exit(0);

# Go to / to grab a cookie
r = http_send_recv3(port: port, method: 'GET', item: "/");
if (isnull(r)) exit(0);
# No need to test the Server field again here.

cmd = 'volatile.authentication_failed=true&volatile.login=true&webvars.username=admin&webvars.password=admin';

r = http_send_recv3(port: port, method: 'POST', item: '/', data: cmd, 
 add_headers: make_array('Content-Type', 'application/x-www-form-urlencoded') );
if (isnull(r) || ">Invalid username or password.<" >< r[2]) exit(0);

# hash=MD5("admin")
if (egrep(string: r[1], pattern: '^Set-Cookie:[ \t]*authpassword7=21232f297a57a5a743894a0e4a801fc3;'))
 security_hole(port);
