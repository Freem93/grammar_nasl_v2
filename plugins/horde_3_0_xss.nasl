#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB refs (4/30/09)


include("compat.inc");

if (description)
{
  script_id(16162);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/01/14 03:46:10 $");

  script_cve_id("CVE-2005-0378");
  script_bugtraq_id(12255);
  script_osvdb_id(12900, 12901);

  script_name(english:"Horde < 3.0.1 Multiple Script XSS");
  script_summary(english:"Checks for XSS flaws in Horde 3.0");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is hosting a PHP application that is affected by
multiple cross-site scripting vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote host is running at least one instance of Horde version
3.0, which suffers from two cross-site scripting vulnerabilities.
Through specially crafted GET requests to the remote host, an attacker
can cause a third-party user to unknowingly run arbitrary JavaScript
code.");
  # http://web.archive.org/web/20050204104355/http://www.hyperdose.com/advisories/H2005-01.txt
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?85f120e3");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Horde version 3.0.1 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/13");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/04");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:horde_application_framework");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 George A. Theall");
  script_family(english:"CGI abuses : XSS");
  script_dependencie("global_settings.nasl", "horde_detect.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("www/horde");
  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
debug_print("searching for XSS flaws in Horde 3.0 on port ", port, ".");

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/horde"));
if (isnull(installs)) exit(0, "Horde was not detected on port "+port);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    debug_print("checking version ", ver, " under ", dir, ".");

    if (ereg(pattern:"^3\.0$", string:ver)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
