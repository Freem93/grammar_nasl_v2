#
# This script was written by Frank Berger <dev.null@fm-berger.de>
# <http://www.fm-berger.de>
#
# License: GPL v 2.0  http://www.gnu.org/copyleft/gpl.html
#
# See the Nessus Scripts License for details
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, enhanced description, replaced 404 URL (6/10/09)

include("compat.inc");

if (description)
{
 script_id(11918);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2014/07/11 19:10:05 $");

 script_cve_id("CVE-2003-1193");
 script_bugtraq_id(8966);
 script_osvdb_id(2763);

 script_name(english:"Oracle PORTAL_DEMO.ORG_CHART SQL Injection");
 script_summary(english:"Tests for presence of Oracle PORTAL_DEMO.ORG_CHART");

 script_set_attribute(attribute:"synopsis", value:"The remote may be vulnerable to SQL injection attacks.");
 script_set_attribute(attribute:"description", value:
"It is possible to access a demo (PORTAL_DEMO.ORG_CHART) script on the
remote host. Access to these pages should be restricted because it may
be possible to abuse this demo for SQL Injection attacks.

Additional components of the Portal have been reported as vulnerable
to SQL injection attacks but Nessus has not tested for these.");
 # http://web.archive.org/web/20031106062404/http://otn.oracle.com/deploy/security/pdf/2003alert61.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?799792be");
 script_set_attribute(attribute:"solution", value:
"Remove the Execute for Public grant from the PL/SQL package in schema
PORTAL_DEMO (REVOKE execute ON portal_demo.org_chart FROM public;).
Please check also Oracle Security Alert 61 for patch-information.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2003/11/03");
 script_set_attribute(attribute:"patch_publication_date", value:"2003/11/03");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/11/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_portal");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Frank Berger.");
 script_family(english:"Databases");

 script_dependencie("http_version.nasl");
 script_require_keys("www/OracleApache", "Settings/ParanoidReport");
 script_require_ports("Services/www", 80, 7777, 7778, 7779);

 exit(0);
}

include("audit.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

# No way to know for sure if the DEMO is part of Oracle 9i, or newer
# fusion Middleware.  Also, this vulnerability can be patched, and the
# plugin doesn't actually exploit it.
if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);

# Make a request for the Admin_ interface.
 req = http_get(item:"/pls/portal/PORTAL_DEMO.ORG_CHART.SHOW", port:port);
 res = http_keepalive_send_recv(port:port, data:req);
 if ( res == NULL ) exit(0);
 if( "Organization Chart" >< res )
 {
 	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
 }
