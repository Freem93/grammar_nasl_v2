#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(22868);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2006-5200");
  script_bugtraq_id(20438);
  script_osvdb_id(29620);

  script_name(english:"Adobe Breeze Directory Traversal Arbitrary File Access");
  script_summary(english:"Checks version of Adobe Breeze");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be Adobe Breeze, a web-based video
conferencing system. 

The version of Adobe Breeze installed on the remote host reportedly
has an issue with URL parsing.  While specific information about the
issue is currently not available, a remote attacker may be able to 
exploit this to view arbitrary files on the affected host." );
 script_set_attribute(attribute:"see_also", value:"http://www.adobe.com/support/security/bulletins/apsb06-16.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade as necessary to Breeze 5.1 SP2 and install the patch as
described in the vendor advisory referenced above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2006/10/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/10");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/10/10");
 script_cvs_date("$Date: 2013/03/26 21:41:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/a:adobe:breeze_licensed_server");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);


# Make sure the banner is from JRun.
banner = get_http_banner(port:port);
if (!banner || "Server: JRun Web Server" >!< banner) exit(0);

init_cookiejar();
# Grab version information and make sure it's Breeze.

r = http_send_recv3(port: port, item:"/version.txt", method: 'GET');
if (isnull(r)) exit(0);
if (! get_http_cookie(name: 'BREEZESESSION')) exit(0);
res = r[0] + r[1] + '\r\n'+ r[2];

# Extract the version info.
v_min = NULL;
r = NULL;
pat = '^5\\.([0-9]),([0-9]+)';
matches = egrep(pattern:pat, string: res);
if (matches) {
  foreach match (split(matches)) {
    match = chomp(match);
    ver = eregmatch(pattern:pat, string:match);
    if (!isnull(ver)) {
      v_min = int(ver[1]);
      r = int(ver[2]);
      break;
    }
  }
}
if (isnull(v_min) || isnull(r)) exit(0);


# There's a problem if it's [5.0, 5.1 r 172).
if (v_min == 0 || (v_min == 1 && r < 172))
{
  if (report_verbosity > 1)
    report = string(
      "Nessus has determined that the installed version of Breeze is :\n",
      "  5.", v_min, " r. ", r
    );
  else report = NULL;

  security_warning(port:port, extra:report);
  exit(0);
}
