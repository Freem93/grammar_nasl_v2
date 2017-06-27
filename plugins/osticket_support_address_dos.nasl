#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, changed family, added OSVDB ref (4/21/009)


include("compat.inc");

if (description) {
  script_id(13859);
  script_version ("$Revision: 1.8 $");
  script_osvdb_id(53808);
  script_cvs_date("$Date: 2013/01/25 01:19:09 $");

  script_name(english:"osTicket open.php Support Address Crafted Mail Loop Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host may be vulnerable to a denial of service." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of osTicket 1.2.7 or
earlier.  Such versions are subject to a denial of service attack in
open.php if osTicket is configured to receive mails using aliases.  If
so, a remote attacker can generate a mail loop on the target by opening
a ticket with the support address as the contact email address. For 
details, see :

  -  http://www.nessus.org/u?a1aa7bab

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number(s) of osTicket installed 
***** there. It has no way of knowing which method osTicket uses to
***** retrieve mail." );
 script_set_attribute(attribute:"solution", value:
"Configure osTicket to receive mail using POP3." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/30");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Support Address DoS osTicket";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 George A. Theall");

  script_family(english:"CGI abuses");

  script_dependencie("global_settings.nasl", "osticket_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/osticket");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for Support Address DoS vulnerability in osTicket on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/osticket"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^1\.(0|1|2|2\.[0-7])$", string:ver)) {
      security_hole(port);
      exit(0);
    }
  }
}
