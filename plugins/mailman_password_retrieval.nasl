#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/2/09)
# - Revised plugin title (8/13/12)

include("compat.inc");

if (description)
{
  script_id(12253);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2012/08/14 16:26:26 $");

  script_cve_id("CVE-2004-0412");
  script_bugtraq_id(10412);
  script_osvdb_id(6422);
  script_xref(name:"CLSA", value:"CLSA-2004:842");
  script_xref(name:"FLSA", value:"FEDORA-2004-1734");
  script_xref(name:"GLSA", value:"GLSA-200406-04");
  script_xref(name:"MDKSA", value:"MDKSA-2004:051");
 
  script_name(english:"Mailman Crated Email Remote User Password Disclosure");
  script_summary(english:"Checks for Mailman Password Retrieval Vulnerability");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote host is running a mailing list application that is 
affected by a password disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The target is running a version of the Mailman mailing list software
that allows a list subscriber to retrieve the mailman password of any
other subscriber by means of a specially crafted mail message to the
server.  That is, a message sent to $listname-request@$target 
containing the lines :

    password address=$victim
    password address=$subscriber

will return the password of both $victim and $subscriber for the list
$listname@$target. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of Mailman installed
***** there." );
  script_set_attribute(attribute:"see_also", value:"http://mail.python.org/pipermail/mailman-announce/2004-May/000072.html" );
  script_set_attribute(attribute:"solution", value:
"Upgrade to Mailman version 2.1.5 or newer as this reportedly fixes 
the issue." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/26");
  script_set_attribute(attribute:"vuln_publication_date", value: "2004/05/15");
  script_set_attribute(attribute:"plugin_type", value: "remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:gnu:mailman");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2012 George A. Theall");
  script_family(english:"Misc.");
  script_dependencie("global_settings.nasl", "http_version.nasl", "mailman_detect.nasl");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if (!get_port_state(port)) exit(0);
debug_print(level: 2, "checking for Mailman Password Retrieval vulnerability on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/Mailman"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print(level:2, "checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^2\.1(b[2-6]|rc1|\.[1-4]([^0-9]|$))", string:ver)) {
      security_warning(port);
      exit(0);
    }
  }
}
