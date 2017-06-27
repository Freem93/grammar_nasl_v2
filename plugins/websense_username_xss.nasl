#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29306);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2007-6312");
  script_bugtraq_id(26793);
  script_osvdb_id(39155);

  script_name(english:"Websense Reporting Tools WsCgiLogin.exe username Parameter XSS");
  script_summary(english:"Checks for an XSS flaw in Websense Reporting Tools");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a script that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Websense, a commercial suite of web
filtering products. 

The remote instance of Websense fails to sanitize user input to the
'UserName' parameter of the 'Websense/cgi-bin/WsCgiLogin.exe' script
before using it to generate dynamic content.  An unauthenticated
remote attacker may be able to leverage this issue to inject arbitrary
HTML or script code into a user's browser to be executed within the
security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?430117ea" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2007/Dec/123" );
 script_set_attribute(attribute:"see_also", value:"http://www.websense.com/SupportPortal/SupportKbs/1840.aspx" );
 script_set_attribute(attribute:"solution", value:
"Apply the Hotfix referenced in the vendor advisory above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/12/11");
 script_cvs_date("$Date: 2016/11/03 14:16:36 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default: 80, embedded: TRUE);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# Try to exploit the issue.
xss = string("<script>alert('", SCRIPT_NAME, "')</script>");
exploit = string('nessus">', xss);

w = http_send_recv3(method:"GET",
  item:string(
    "/Websense/cgi-bin/WsCgiLogin.exe?",
    "Page=login&",
    "UserName=", urlencode(str:exploit)
  ), 
  port:port
);
if (isnull(w)) exit(0);
res = w[2];

# There's a problem if...
if (
  # it's Websense and ...
  'alt="Websense.com"' >< res && 
  # the output complains about our "user name".
  ' name="UserName"' >< res &&
  string('value="', exploit, '">') >< res
)
{
  security_warning(port);
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
