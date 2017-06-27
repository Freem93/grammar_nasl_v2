#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29745);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/05/01 21:38:51 $");

  script_bugtraq_id(26885);
  script_osvdb_id(39518);
  script_xref(name:"Secunia", value:"28130");

  script_name(english:"WordPress 'query.php' is_admin() Function Information Disclosure");
  script_summary(english:"Sends a request with 'wp-admin/' in the query string.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an information disclosure vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress running on the remote web server is affected
by an information disclosure vulnerability due to improper checks for
administrative credentials by the is_admin() function in
'wp-includes/query.php'. A remote attacker can exploit this, via a
specially crafted URL containing the string 'wp-admin/', to view posts
for which the status is classified as 'future', 'draft', or 'pending',
which would otherwise be available only to authenticated users.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/485160/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"https://core.trac.wordpress.org/ticket/5487");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/news/2007/12/wordpress-232/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to WordPress version 2.3.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/12/14");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2015 Tenable Network Security, Inc.");

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

dir = install['path'];
install_url = build_url(port:port, qs:dir);
output = '';

# Try to exploit the flaw.
url = '/index.php/nessus-wp-admin/';

res = http_send_recv3(
  method:"GET",
  item:dir + url,
  port:port,
  exit_on_fail:TRUE
);

# The fix results in a redirect so there's a problem if we get posts instead.
if (
  ('<div class="post"' >< res[2]) &&
  (res[2] =~ 'id="post-(\\d)+') &&
  (res[2] =~ '<small>(.+)<\\!-- by (.+) --></small>')
)
{
  # On affected versions, posts saved as drafts should report a post
  # date of November 30th, 1999.
  if ('<small>November 30th, 1999' >< res[2])
  {
    pos = stridx(res[2], '<small>November 30th, 1999');
    # Grab enough of the post to make it more visible in the report
    if (pos > 0 && !empty_or_null(pos)) output = substr(res[2], (pos - 200));
  }
  if (empty_or_null(output))
  {
    # However if there is not a draft, just grab 1st post for report
    output = strstr(res[2], '<div class="post"');
    if (empty_or_null(output)) output = res[2]; # Should never happen
  }
  security_report_v4(
    port        : port,
    severity    : SECURITY_WARNING,
    generic     : TRUE,
    request     : make_list(install_url + url),
    output      : chomp(output)
  );
  exit(0);
}
else audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
