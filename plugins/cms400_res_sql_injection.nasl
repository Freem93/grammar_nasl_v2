#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33269);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2008-5122");
  script_bugtraq_id(29857);
  script_osvdb_id(46512);
  script_xref(name:"Secunia", value:"30824");

  script_name(english:"Ektron CMS400.NET WorkArea/ContentRatingGraph.aspx res Parameter SQL Injection");
  script_summary(english:"Tries to generate an error");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a .NET application that is susceptible
to a SQL injection attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running CMS400.NET, a .NET content management
solution. 

The version of CMS400.NET installed on the remote host fails to
sanitize user-supplied input to the 'res' parameter of the
'WorkArea/ContentRatingGraph.aspx' script before using it in a
database query.  An unauthenticated attacker may be able to exploit
this issue to manipulate database queries to disclose sensitive
information, bypass authentication, or even attack the underlying
database." );
 script_set_attribute(attribute:"see_also", value:"http://dev.ektron.com/kb_article.aspx?id=18294" );
 script_set_attribute(attribute:"see_also", value:"http://dev.ektron.com/forum.aspx?g=posts&t=18296" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(89);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/26");
 script_cvs_date("$Date: 2016/05/04 18:02:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:ektron:cms4000.net");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_asp(port:port)) exit(0);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/cms", "/cms400", "/cms400.net", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  exploit = string("' AND ", SCRIPT_NAME, " --");

  r = http_send_recv3(method:"GET", port: port,
    item:string(
      dir, "/WorkArea/ContentRatingGraph.aspx?",
      "type=time&",
      "view=day&",
      "res_type=content&",
      "res=1", urlencode(str:exploit), "&",
      "EndDate=", urlencode(str:"5/10/2008 12:00:00 AM")));
  if (isnull(r)) exit(0);
  res = r[2];

  # If we see an error involving our exploit, report the problem.
  if (
    "SqlClient.SqlException" >< res && 
    string("after the character string ", exploit) >< res
  )
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
  # If we see a generic server error, rerun the query without the exploit.
  else if (
    "An application error occurred" >< res &&
    "custom error settings" >< res
  )
  {
    r = http_send_recv3(method:"GET", port: port,
      item:string(
        dir, "/WorkArea/ContentRatingGraph.aspx?",
        "type=time&",
        "view=day&",
        "res_type=content&",
        "res=1&",
        "EndDate=", urlencode(str:"5/10/2008 12:00:00 AM")));
    if (isnull(r)) exit(0);
    res2 = r[2];

    # There's a problem if we see a GIF this time.
    if (res2 && stridx(res2, "GIF") == 0)
    {
      security_hole(port);
      set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
      exit(0);
    }
  }
}
