#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Revised plugin title (4/30/09)
# - Revised plugin title (8/13/12)


include("compat.inc");

if (description)
{
  script_id(13857);
  script_version ("$Revision: 1.22 $");
  script_cvs_date("$Date: 2015/01/14 03:46:10 $");

  script_cve_id("CVE-2004-1443");
  script_bugtraq_id(10845);
  script_osvdb_id(8293);

  script_name(english:"Horde IMP with MSIE MIME Viewer Email Message XSS");
  script_summary(english:"Checks for HTML+TIME Vulnerability in IMP");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is running a PHP application that is affected by
a cross-site scripting vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote server is running at least one instance of IMP whose 
version number is 3.2.4 or lower.  Such versions are vulnerable to a
cross-scripting attack whereby an attacker may be able to inject 
arbitrary content, including script, in a specially crafted MIME
message.  To have an effect, the victim must be using Internet 
Explorer to access IMP and be using the inline MIME viewer for HTML 
messages. 

Note : Nessus has determined the vulnerability exists on the target
simply by looking at the version number of IMP installed there, it has
not attempted to actually exploit the vulnerability.");
  script_set_attribute(attribute:"see_also", value:"http://www.greymagic.com/security/advisories/gm005-mc/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IMP version 3.2.5 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

  script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/03");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:horde:imp");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_family(english:"CGI abuses : XSS");

  script_dependencie("global_settings.nasl", "imp_detect.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: searching for HTML+TIME XSS vulnerability in IMP on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);

# Check each installed instance, stopping if we find a vulnerability.
installs = get_kb_list(string("www/", port, "/imp"));
if (isnull(installs)) exit(0);
foreach install (installs) {
  matches = eregmatch(string:install, pattern:"^(.+) under (/.*)$");
  if (!isnull(matches)) {
    ver = matches[1];
    dir = matches[2];
    if (debug_level) display("debug: checking version ", ver, " under ", dir, ".\n");

    if (ereg(pattern:"^(1\.|2\.|3\.(0|1|2|2\.[1-4]))$", string:ver)) {
      security_warning(port);
      set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
      exit(0);
    }
  }
}
