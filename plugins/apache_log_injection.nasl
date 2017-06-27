#
# This script was written by George A. Theall, <theall@tifaware.com>.
#
# See the Nessus Scripts License for details.
#

# Changes by Tenable:
# - Standardized title (4/2/2009)
# - Added Synopsis, See Also, CVSS Vector (4/9/2009)

include("compat.inc");

if (description)
{
  script_id(12239);
  script_version("$Revision: 1.30 $");
  script_cvs_date("$Date: 2015/08/04 20:57:14 $");

  script_cve_id("CVE-2003-0020");
  script_bugtraq_id(9930);
  script_osvdb_id(4382);
  script_xref(name:"APPLE-SA", value:"APPLE-SA-2004-05-03");
  script_xref(name:"CLSA", value:"CLSA-2004");
  script_xref(name:"HPSB", value:"HPSBUX01022");
  script_xref(name:"MDKSA", value:"MDKSA-2003");
  script_xref(name:"OpenPKG-SA", value:"OpenPKG-SA-2004.021-apache");
  script_xref(name:"RHSA", value:"2003:082");
  script_xref(name:"RHSA", value:"2003:083");
  script_xref(name:"RHSA", value:"2003:104");
  script_xref(name:"RHSA", value:"2003:139");
  script_xref(name:"RHSA", value:"2003:243");
  script_xref(name:"RHSA", value:"2003:244");
  script_xref(name:"Secunia", value:"11681");
  script_xref(name:"Secunia", value:"11705");
  script_xref(name:"Secunia", value:"11719");
  script_xref(name:"Secunia", value:"11859");
  script_xref(name:"Secunia", value:"12246");
  script_xref(name:"SSA", value:"SSA");
  script_xref(name:"SuSE", value:"SuSE-SA");
  script_xref(name:"TLSA", value:"TLSA-2004-11");
  script_xref(name:"TSLSA", value:"TSLSA-2004-0017");

  script_name(english:"Apache < 1.3.31 / 2.0.49 Log Entry Terminal Escape Sequence Injection");
  script_summary(english:"Checks for Apache Error Log Escape Sequence Injection Vulnerability");

  script_set_attribute(attribute:"synopsis", value:"The remote web server is affected by a log injection vulnerability.");
  script_set_attribute(attribute:"description", value:
"The target is running an Apache web server that allows for the
injection of arbitrary escape sequences into its error logs. An
attacker might use this vulnerability in an attempt to exploit similar
vulnerabilities in terminal emulators.

***** Nessus has determined the vulnerability exists only by looking
at ***** the Server header returned by the web server running on the
target.");
  script_set_attribute(attribute:"solution", value:"Upgrade to Apache version 1.3.31 or 2.0.49 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2003/02/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/17");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:http_server");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2015 George A. Theall");

  script_family(english:"Web Servers");

  script_dependencie("find_service1.nasl", "global_settings.nasl", "http_version.nasl", "redhat-RHSA-2003-244.nasl", "redhat_fixes.nasl", "macosx_SecUpd20040503.nasl", "macosx_SecUpd20040126.nasl", "macosx_SecUpd20041202.nasl");
  script_require_keys("www/apache", "Settings/ParanoidReport");
  script_require_ports("Services/www", 80);
  exit(0);
}

include("audit.inc");
include("backport.inc");
include("global_settings.inc");
include("http_func.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

host = get_host_name();
port = get_http_port(default:80);
if (debug_level) display("debug: checking for Apache Error Log Escape Sequence Injection vulnerability on ", host, ":", port, ".\n");

if (!get_port_state(port)) exit(0);
if (get_kb_item("CVE-2003-0020") || get_kb_item("RHSA-2003-244")) exit(0);

# Check the web server's banner for the version.
banner = get_http_banner(port: port);
if (!banner) exit(0);
banner = get_backport_banner(banner:banner);

sig = strstr(banner, "Server:");
if (!sig) exit(0);
if (debug_level) display("debug: server sig = >>", sig, "<<.\n");

# For affected versions of Apache, see:
#   - http://www.apacheweek.com/features/security-13
#   - http://www.apacheweek.com/features/security-20
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.([0-2]\.[0-9]|3\.([0-9][^0-9]|[0-2][0-9]))|2\.0.([0-9][^0-9]|[0-3][0-9]|4[0-8]))", string:sig)) {
  security_warning(port);
}
