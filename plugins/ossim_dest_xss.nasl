#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31133);
  script_version("$Revision: 1.18 $");

  script_cve_id("CVE-2008-0919");
  script_bugtraq_id(27929);
  script_osvdb_id(42007);
  script_xref(name:"EDB-ID", value:"5171");
  script_xref(name:"Secunia", value:"29046");

  script_name(english:"OSSIM Framework session/login.php dest Parameter XSS");
  script_summary(english:"Tries to inject script code into login form");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OSSIM (Open Source Security Information
Management), a suite of security tools managed by a web-based
front-end. 

The version of OSSIM installed on the remote host fails to sanitize
user input to the 'dest' parameter of the 'session/login.php' script
before using it to generate dynamic HTML output.  An unauthenticated
attacker can exploit this to inject arbitrary HTML and script code
into a user's browser to be executed within the security context of
the affected site. 

Note that there is also reportedly a SQL injection vulnerability
associated with this version of OSSIM, although Nessus has not checked
for it." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/488450/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.ossim.net/news.php#75" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to OSSIM 0.9.9p1 / Installer 1.0.4 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/22");
 script_cvs_date("$Date: 2016/05/20 14:21:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");


port = get_http_port(default:80, embedded: 0);
if (!can_host_php(port:port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

exploit = string('nessus">', "<script>alert('", SCRIPT_NAME, "')</script><!-- ");


# Loop through directories.
if (thorough_tests) dirs = list_uniq(make_list("/ossim", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Inject some script code.
  w = http_send_recv3(method:"GET", 
    item:string(
      dir, "/session/login.php?",
      "dest=", urlencode(str:exploit)
    ),
    port:port
  );
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  res = w[2];

  # There's a problem if we see our exploit in the form.
  if (
    (
      "<title> OSSIM Framework Login" >< res ||
      "<h1> OSSIM Login" >< res ||
      'alt="OSSIM logo"' >< res
    ) &&
    string('type="hidden" name="dest" value="', exploit, '">') >< res
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
