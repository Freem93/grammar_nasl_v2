#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Changed family (8/6/09)


include("compat.inc");

if (description) {
  script_id(12637);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2004-2284");
  script_bugtraq_id(10637);
  script_osvdb_id(7474);

  script_name(english:"Open WebMail vacation.pl Arbitrary Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary commands may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Open WebMail in which
the vacation.pl component fails to sufficiently validate user input. 
This failure enables remote attackers to execute arbitrary programs on
a target using the privileges under which the web server operates. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:04.txt

If safe_checks are disabled, Nessus attempts to create the file
/tmp/nessus_openwebmail_vacation_input_validation on the target." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Open WebMail version 2.32 20040629 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/06");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/06");
 script_cvs_date("$Date: 2011/03/17 01:57:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for Arbitrary Command Execution flaw in Open WebMail's vacation.pl");
  script_category(ACT_GATHER_INFO);
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
if (debug_level) display("debug: checking for Arbitrary Command Execution flaw in vacation.pl in Open WebMail on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: intermediate releases of 2.32 from 20040527 - 20040628 are 
    #     vulnerable, as are 2.32 and earlier releases.
    pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|6[01]|62[0-8])))";
    if (ereg(pattern:pat, string:ver)) {
      # At this point, we know the target is running a potentially vulnerable
      # version. Still, we need to verify that vacation.pl is accessible since
      # one workaround is to simply remove the script from the CGI directory.
      url = string(dir, "/vacation.pl");
      # If safe_checks is disabled, I'll try to create 
      # /tmp/nessus_openwebmail_vacation_input_validation as a PoC 
      # although AFAIK there's no programmatic way to verify this worked 
      # since the script doesn't display results of any commands that might
      # be run.
      if (safe_checks() == 0) url += "?-i+-p/tmp+-ftouch%20/tmp/nessus_openwebmail_vacation_input_validation|";
      if (debug_level) display("debug: retrieving ", url, "...\n");

      req = http_get(item:url, port:port);
      res = http_keepalive_send_recv(port:port, data:req);
      if (isnull(res)) exit(0);           # can't connect
      if (debug_level) display("debug: res =>>", res, "<<\n");

      if (egrep(string:res, pattern:"^HTTP/.* 200 OK")) {
        security_hole(port);
        exit(0);
      }
    }
  }
}
