#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21757);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2006-3245");
  script_bugtraq_id(18663);
  script_osvdb_id(26833);

  script_name(english:"mvnForum activatemember Multiple Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in mvnForum's activatemember script");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is affected by
several cross-site scripting issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running mvnForum, an open source, forum application
based on Java J2EE. 

The version of mvnForum installed on the remote host fails to sanitize
user-supplied input to the 'activatecode' and 'member' parameters of
the 'activatemember' script before using it to generate dynamic web
content.  Successful exploitation of this issue may lead to the
execution of arbitrary HTML and script code in a user's browser within
the context of the affected application." );
 script_set_attribute(attribute:"see_also", value:"http://pridels0.blogspot.com/2006/06/mvnforum-xss-vuln.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/06/27");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/06/24");
 script_cvs_date("$Date: 2015/01/14 03:46:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mvnforum:mvnforum");
script_end_attributes();

 
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");
 
  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# A simple alert.
xss = string('"', "><script>alert('", SCRIPT_NAME, "')</script>");
exss = urlencode(str:xss);

# Loop through various directories.
if (thorough_tests) dirs = list_uniq(make_list("/mvnforum", "/forum", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try to exploit the issue.
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/activatemember?",
      "activatecode=&",
      "member=", urlencode(str:xss)
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if...
  if (
    # it looks like mvnForum and...
    'form action="activatememberprocess"' >< res &&
    # we see our XSS.
    string('name="member" value="', xss) >< res
  )
  {
    security_note(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
