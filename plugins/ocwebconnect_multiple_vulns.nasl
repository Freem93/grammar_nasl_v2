#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(17214);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2004-0465", "CVE-2004-0466");
  script_bugtraq_id(12613);
  script_osvdb_id(14009, 14010);

  script_name(english:"OpenConnect WebConnect < 6.5.1 Multiple Vulnerabilities");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Java application that is vulnerable
to multiple attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenConnect WebConnect, a web-based
graphical user interface that gives remote users console access to
mainframe, midrange, and Unix systems using a Java-based telnet
console which communicates securely over HTTP.  OC WebConnect 6.44 and
6.5 (and possibly previous versions) have multiple remote
vulnerabilities :

  - A remote attacker can bring about a denial of service by 
    sending an HTTP GET or POST request with an MS-DOS device 
    name in it (Windows platforms only). 

  - A read-only directory traversal vulnerability in 'jretest.html'
    allows exposure of files formatted in an INI-style format (any 
    platform)." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110910838600145");
 script_set_attribute(attribute:"solution", value:
"Upgrade to OpenConnect WebConnect 6.5.1 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/02/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/21");
 script_cvs_date("$Date: 2014/01/03 22:36:51 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "Checks for multiple vulnerabilities in OpenConnect WebConnect < 6.5.1";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 
 script_dependencies("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


global_var wc_ver, wc_platform;


# This function tries to identify the version and platform of WebConnect 
# based on an array of lines. If successful, it sets the global 
# variables "wc_ver" and "wc_platform".
function id_webconnect(page) {
  local_var pat, matches, match;

  # Some pages embed the server version and platform in a Java applet.
  pat = 'PARAM NAME="serverVersion" VALUE="WC(.+)"';
  matches = egrep(pattern:pat, string:page);
  foreach match (split(matches)) {
    match = chomp(match);
    wc_ver = eregmatch(pattern:pat, string:match);
    if (wc_ver == NULL) break;
    wc_ver = wc_ver[1];
  }
  pat = 'PARAM NAME="serverType" VALUE="(.+)"';
  matches = egrep(pattern:pat, string:page);
  foreach match (split(matches)) {
    match = chomp(match);
    wc_platform = eregmatch(pattern:pat, string:match);
    if (wc_platform == NULL) break;
    wc_platform = wc_platform[1];
  }

  # And others have it as plain HTML in a frame.
  if (wc_ver == NULL) {
    pat = '<b>Version WC(.+)</b>';
    matches = egrep(pattern:pat, string:page);
    foreach match (split(matches)) {
      match = chomp(match);
      wc_ver = eregmatch(pattern:pat, string:match);
      if (wc_ver == NULL) break;
      wc_ver = wc_ver[1];
    }
  }
}


port = get_http_port(default:80);

# Check whether the server is running OC WebConnect.
#
# nb: the server doesn't seem to add a Server: header but does 
#     put its name in the title of both /jretest.html if it
#     exists and an error page otherwise.
w = http_send_recv3(method:"GET", item:"/jretest.html", port:port);
if (isnull(w)) exit(1, "the web server on port "+port+" did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);
if ( !egrep(pattern:"TITLE>OC://WebConnect", string:res) ) exit(0);


# Determine if jretest.html exists.
if ( egrep(pattern:"HTTP/.+ 200 OK", string:res) ) jretest_exists = 1;
else jretest_exists = 0;


# Determine OC WebConnect's version number and platform.
#
# nb: look at selected frames on the main page and then in linked pages
#     looking for telltale identifiers.
w = http_send_recv3(method:"GET", item:"/", port:port);
if (isnull(w)) exit(1, "the web server on port "+port+" did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

pat = 'SRC="([^"]+)"';
matches = egrep(pattern:pat, string:res);
foreach match (split(matches)) {
  match = chomp(match);
  frame = eregmatch(pattern:pat, string:match);
  if (frame == NULL) break;
  frame = frame[1];
  if (frame[0] != '/') frame = '/' + frame;

  if (frame =~ "\.html\?.*lang=") {
    w = http_send_recv3(method:"GET", item:frame, port:port);
    if (isnull(w)) exit(1, "the web server on port "+port+" did not answer");
    html = strcat(w[0], w[1], '\r\n', w[2]);

    # nb: scan the frame's html since sometimes the version number
    #     can be found in a top / left frame.
    id_webconnect(page:html);

    # nb: ideally, though, we want to find the Java applet since 
    #     it has both version and platform so we'll look through
    #     selected local links too.
    pat2 = 'HREF="(/[^"]+)"';
    matches2 = egrep(pattern:pat2, string:html);
    foreach match2 (split(matches2)) {
      match2 = chomp(match2);
      link = eregmatch(pattern:pat2, string:match2);
      if (link == NULL) break;
      link = link[1];

      if (link =~ "\.html\?.*lang=") {
        w = http_send_recv3(method:"GET", item:frame, port:port);
    	if (isnull(w)) exit(1, "the web server on port "+port+" did not answer");
	html = strcat(w[0], w[1], '\r\n', w[2]);

        id_webconnect(page:html);
        # If the version and platform were both identified, we're done.
        if (!isnull(wc_ver) && !isnull(wc_platform)) break;
      }
    }

    # If the version and platform were both identified, we're done.
    if (!isnull(wc_ver) && !isnull(wc_platform)) break;
  }
}


# Finally, determine whether the target is vulnerable.
#
if (wc_ver =~ "^([0-5]|6\.([0-4]|5$|5\.0))") {
  if (isnull(wc_platform) || wc_platform =~ "^Win") security_warning(port);
  else if (jretest_exists) security_warning(port);
}
