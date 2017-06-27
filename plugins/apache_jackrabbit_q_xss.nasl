#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35452);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2009-0026");
  script_bugtraq_id(33360);
  script_osvdb_id(51467, 51468);
  script_xref(name:"Secunia", value:"33576");

  script_name(english:"Apache Jackrabbit 'q' Parameter XSS");
  script_summary(english:"Tries to inject script code through Jackrabbit's search.jsp / swr.jsp pages");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java web application that is affected
by two cross-site scripting vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Apache Jackrabbit, an open source webapp
that implements the Java Content Repository (JCR) API. 

The version of Apache Jackrabbit running on the remote host fails to
sanitize user input to the 'q' parameter of the 'search.jsp' and
'swr.jsp' pages before including it in dynamic HTML output.  An
attacker can exploit these issues to inject arbitrary HTML and script
code into a user's browser to be executed within the security context
of the affected site." );
 script_set_attribute(attribute:"see_also", value:"https://issues.apache.org/jira/browse/JCR-1925" );
  # http://web.archive.org/web/20090418221420/http://apache.org/dist/jackrabbit/RELEASE-NOTES-1.5.2.txt
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8112eea3" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/500196/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache Jackrabbit 1.5.2 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/23");
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:jackrabbit");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


now = unixtime();
alert = string("<script>alert(", now, ")</script>");
ualert = urlencode(str:alert, unreserved:"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_.!~*'()-]/");
if (thorough_tests) 
{
  exploits = make_list(
    string('/search.jsp?q=%25%22', ualert),
    string('/swr.jsp?q=%25"', alert, '&swrnum=1')
  );
}
else
{
  exploits = make_list(
    string('/search.jsp?q=%25%22', ualert)
  );
}


# Loop through directories.
#
# nb: Jackrabbit's install directory probably won't be discovered so we'll always look under "/jackrabbit".
dirs = list_uniq(make_list("/jackrabbit", cgi_dirs()));

foreach dir (dirs)
{
  foreach exploit (exploits)
  {
    url = string(dir, exploit);

    res = http_send_recv3(method:"GET", item:url, port:port);
    if (res == NULL) exit(0);

    # There's a problem if we see our exploit in the form.
    if (
      (
        "search.jsp" >< exploit &&
        "Exception building query: org.apache.jackrabbit" >< res[2] &&
        string('Encountered: <EOF> after : "\\"', alert, '"') >< res[2]
      ) ||
      (
        "swr.jsp" >< exploit &&
        'alt="Apache Jackrabbit"' >< res[2] &&
        string('results for <b>%"', alert, '</b>') >< res[2]
      )
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

      exit(0);
    }
  }
}
