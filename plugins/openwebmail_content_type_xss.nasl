#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref (5/21/09)
# - Revised plugin description-fixed typo (06/02/2011)


include("compat.inc");

if (description) {
  script_id(12262);
  script_version ("$Revision: 1.18 $");

  script_bugtraq_id(10667);
  script_osvdb_id(54626);
 
  script_name(english:"Open WebMail Multiple Content Header XSS");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application may be vulnerable to cross-site scripting." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of Open WebMail whose
version is 2.32 or earlier.  Such versions are vulnerable to a cross-
site scripting attack whereby an attacker can cause a victim to
unknowingly run arbitrary JavaScript code by reading a MIME message
with a specially crafted Content-Type or Content-Description header. 
For further information, see :

  http://www.openwebmail.org/openwebmail/download/cert/advisories/SA-04:05.txt
  http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-2.txt
  http://www.rs-labs.com/adv/RS-Labs-Advisory-2004-1.txt

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Open WebMail
***** installed there." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Open WebMail version 2.32 20040603 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/06/08");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_summary(english:"Checks for Content-Type XSS flaw in Open WebMail");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("global_settings.nasl", "openwebmail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);

if (!get_port_state(port)) exit(0);
if (debug_level) display("debug: checking for Content-Type XSS flaw in Open WebMail on ", host, ":", port, ".\n");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/openwebmail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    # nb: intermediate releases of 2.32 from 20040527 - 20040602 are 
    #     vulnerable, as are 2.32 and earlier releases.
    pat = "^(1\.|2\.([0-2]|3[01]|32$|32 20040(5|60[12])))";
    if (ereg(pattern:pat, string:ver)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
