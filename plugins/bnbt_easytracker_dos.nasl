#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(19548);
  script_version("$Revision: 1.16 $");

  script_cve_id("CVE-2005-2806");
  script_bugtraq_id(14700);
  script_osvdb_id(19069);

  script_name(english:"BNBT EasyTracker Malformed GET Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to denial of service attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BNBT EasyTracker, a packaged BitTorrent
Tracker Installer for Windows. 

The remote version of BNBT EasyTracker fails to properly handle
malformed HTTP requests, making it prone to denial of service attacks. 
An attacker can crash the application by sending a request with a
header line consisting of only a ':'." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/409621" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/08/31");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/08/29");
 script_cvs_date("$Date: 2011/03/14 21:48:01 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for malformed request denial of service vulnerability in BNBT EasyTracker");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Denial of Service");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 6969);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:6969);

# Grab the initial page.
res = http_get_cache(item:"/", port:port, exit_on_fail: 1);

# If it looks like BNBT EasyTracker...
if ("<title>BNBT Tracker Info</title>" >< res) {

  # If safe checks are enabled...
  if (safe_checks()) {
    pat = 'POWERED BY <a href="http://bnbteasytracker.sourceforge.net".+The Trinity Edition of BNBT - Build (.+) - Click';
    matches = egrep(string:res, pattern:pat);
    if (matches) {
      foreach match (split(matches)) {
        match = chomp(match);
        ver = eregmatch(pattern:pat, string:match);
        if (!isnull(ver)) {
          ver = ver[1];
          # nb: see <http://bnbteasytracker.sourceforge.net/changelog.php>
          #     for version numbers.
          if (ver =~ "^(200[0-4]\.|[0-6]\.|7\.([0-6]r|7r3\.2004))") {
            security_warning(port:port, extra:
"Nessus has determined the vulnerability exists on the remote host 
simply by looking at the version number of BNBT EasyTracker 
installed there");

            exit(0);
          }
          break;
        }
      }
    }
  }
  # Otherwise, try to crash it.
  else {
    r = http_send_recv_buf(port: port, data: 'GET /index.htm HTTP/1.1\r\n:\r\n\r\n');
    # Shouldn't we call http_is_dead?
    if (isnull(r)) {
        security_warning(port);
        exit(0);
    }
  }
}
