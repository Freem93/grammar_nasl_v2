#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14632);
  script_bugtraq_id(6740);
  script_osvdb_id(7334);
  script_version("$Revision: 1.10 $");

# script_cve_id("CVE-MAP-NOMATCH");
# NOTE: no CVE id assigned (gat, 09/2004)
 
  script_name(english:"IlohaMail Attachment Arbitrary File Create/Overwrite");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
a file creation vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of IlohaMail version
0.7.9-RC2 or earlier.  Such versions do not properly check the upload
path for file attachments, which could allow an attacker to place a file
on the target in a location writable by the web user if the file-based
backend is in use. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of IlohaMail 
***** installed there." );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?78be3350" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.7.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/02/06");
 script_cvs_date("$Date: 2011/12/16 23:10:27 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Attachment Upload vulnerability in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 George A. Theall");

  family["english"] = "CGI abuses";
  script_family(english:family["english"]);

  script_dependencie("global_settings.nasl", "ilohamail_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for IlohaMail Attachment Upload vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerable version.
installs = get_kb_list(string("www/", port, "/ilohamail"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ver =~ "^0\.([0-6].*|7\.([0-8](-Devel)?|9-.+)$)") {
      security_warning(port);
      exit(0);
    }
  }
}
