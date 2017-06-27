#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22413);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2006-4957");
  script_bugtraq_id(20105);
  script_osvdb_id(29028);
  script_xref(name:"EDB-ID", value:"2397");

  script_name(english:"MyReview Admin.php email Parameter SQL Injection");
  script_summary(english:"Checks for SQL injection flaw in MyReview");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MyReview, an open source paper submission
and review web application. 

The version of MyReview installed on the remote host fails to properly
sanitize input to the 'email' parameter before using it in the
'GetMember' function in a database query.  Regardless of PHP's
'magic_quotes_gpc' and 'register_globals' settings, an unauthenticated
attacker may be able to exploit this issue to uncover sensitive
information such as password hashes, modify data, launch attacks
against the underlying database, etc." );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/09/19");
 script_cvs_date("$Date: 2013/01/11 22:59:17 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:the_myreview_system:myreview");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0, "The web server on port "+port+" does not support PHP");
if (get_kb_item("www/no404/" + port)) exit(0, "The web server on port "+port+" does not return 404 codes");


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/myreview", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the affected script exists.
  url = string(dir, "/Admin.php");
  w = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # If it does...
  if (
    'Copyright: Philippe Rigaux' &&
    ' NAME="email" VALUE=""' >< res &&
    ' NAME="motDePasse" VALUE=""' >< res
  )
  {
    # Try to exploit the flaw to generate a syntax error.
    email = string("'", SCRIPT_NAME);
    postdata = string(
      "email=", email, "&",
      "motDePasse=a&",
      "ident=Log+in"
    );
    w = http_send_recv3(method:"POST", port: port, item: url,
      content_type: "application/x-www-form-urlencoded",
      data: postdata);
    if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
    res = w[2];

    # There's a problem if we see an error message with our script name.
    if (string("query: SELECT * FROM PCMember WHERE email = '", email, "'") >< res)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
