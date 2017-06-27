#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#


include("compat.inc");

if (description) {
  script_id(14633);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2013/01/25 01:19:08 $");

# script_cve_id("CVE-MAP-NOMATCH");
  script_osvdb_id(7402);
# NOTE: no CVE id assigned (gat, 09/2004)
 
  script_name(english:"IlohaMail Forged GET/POST Arbitrary Contacts Deletion");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a webmail application that is is affected
by a contacts deletion vulnerability." );
 script_set_attribute(attribute:"description", value:
"The target is running at least one instance of IlohaMail version
0.7.9-RC2 or earlier.  Such versions contain a flaw that enables an
authenticated user to delete contacts belonging to any user provided
the DB-based backend is used to store contacts.  The flaw arises
because ownership of 'delete_item' is not checked when deleting
entries in include/save_contacts.MySQL.inc. 

***** Nessus has determined the vulnerability exists on the target
***** simply by looking at the version number of IlohaMail 
***** installed there." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to IlohaMail version 0.7.9 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/01/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Contacts Deletion vulnerability in IlohaMail";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 George A. Theall");

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
if (debug_level) display("debug: searching for IlohaMail Contacts Deletion vulnerability on ", host, ":", port, ".\n");

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
