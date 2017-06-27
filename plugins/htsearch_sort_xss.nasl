#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(28334);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2007-6110");
  script_bugtraq_id(26610);
  script_osvdb_id(40229);

  script_name(english:"ht://dig htsearch sort Parameter XSS");
  script_summary(english:"Tries to exploit an XSS issue in htsearch");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script affected by a cross-site
scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The htsearch CGI script is accessible through the remote web server. 
htsearch is a component of ht://Dig used to index and search documents
such as web pages. 

The version of htsearch installed on the remote host fails to sanitize
user-supplied input to the 'sort' parameter before using it to
generate dynamic output.  An unauthenticated, remote attacker may be
able to leverage this issue to inject arbitrary HTML or script code
into a user's browser to be executed within the security context of
the affected site." );
  # https://www.redhat.com/archives/fedora-package-announce/2007-December/msg00116.html
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a7899e11" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/11/28");
 script_cvs_date("$Date: 2016/05/11 13:32:18 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:htdig:htdig");
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


port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
exss = urlencode(str:xss);


test_cgi_xss(port: port, cgi: "/htsearch", 
  qs: "config=&restrict=&exclude=&method=and&format=builtin-long&sort="
      +exss+"&words="+SCRIPT_NAME,
  pass_str: "No such sort method: `"+xss+"'", pass2_re: "ht://Dig");
