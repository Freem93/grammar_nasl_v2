#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(32319);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-2302");
  script_bugtraq_id(29209);
  script_osvdb_id(45152);
  script_xref(name:"Secunia", value:"30250");

  script_name(english:"Django Administration Application Login Form XSS");
  script_summary(english:"Tries to inject script code into login form");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server uses a web framework that is affected by a
cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is using Django, a high-level Python web framework
designed for rapid development of database-driven websites. 

The administration application included with the version of Django
installed on the remote host fails to sanitize the URL before using it
to generate dynamic HTML output.  An attacker may be able to leverage
this to inject arbitrary HTML and script code into a user's browser to
be executed within the security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://www.djangoproject.com/weblog/2008/may/14/security/" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Django version 0.96.2 / 0.95.3 / 0.91.2 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/05/15");
 script_cvs_date("$Date: 2016/05/05 16:01:12 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
if (thorough_tests) dirs = list_uniq(make_list("/admin", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs)
{
  # Try the exploit.
  r = http_send_recv3(method: "GET", port: port, item:string(dir, "/", urlencode(str:exploit)));
  if (isnull(r)) exit(0);

  # There's a problem if we see our exploit in the form.
  if (
    (
      'Django site admin<' >< r[2] ||
      '>Django administration' >< r[2] ||
      'name="this_is_the_login_form"' >< r[2]
    ) &&
    string('<form action="/admin/', exploit) >< r[2]
  )
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
    exit(0);
  }
}
