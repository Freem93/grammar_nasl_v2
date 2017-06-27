#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32506);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2008-2397");
  script_bugtraq_id(29287);
  script_xref(name:"OSVDB", value:"45371");
  script_xref(name:"Secunia", value:"30307");

  script_name(english:"dotCMS search-results.dot search_query Parameter XSS");
  script_summary(english:"Tries to inject script code into search form");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using dotCMS, an open source J2EE / Java web
content management system. 

The version of dotCMS installed on the remote host fails to sanitize
input to the 'search_query' parameter of the 'search-results.dot'
script before using it to generate dynamic HTML output.  An attacker
may be able to leverage this issue to inject arbitrary HTML and script
code into a user's browser to be executed within the security context
of the affected site." );
 # http://web.archive.org/web/20110424023816/http://jira.dotmarketing.net/browse/DOTCMS-1467
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?ee21a40f" );
  # http://jira.dotmarketing.net/secure/ReleaseNote.jspa?projectId=5803855&styleName=Html&version=10036
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?45e579c5" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to dotCMS version 1.6.0.5 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/06/04");
 script_cvs_date("$Date: 2017/05/16 19:35:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value: "cpe:/a:dotcms:dotcms");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2017 Tenable Network Security, Inc.");

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


exploit = string('nessus">', "<script>alert('", SCRIPT_NAME, "')</script>/");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/home", cgi_dirs()));
else dirs = make_list(cgi_dirs());

q = "search_query=" + urlencode(str:exploit);
foreach script (make_list("search-results.dot", "search_results.dot"))
  if (test_cgi_xss(port: port, cgi: script, qs: q, 
     ctrl_re: 'class="search-results">|<input type="text" name="search_query"',
     pass_re: 'Your search for (<strong>)?"' + exploit ) ) break;
