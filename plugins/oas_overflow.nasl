#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10654);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2014/05/26 01:55:20 $");

 script_cve_id("CVE-2001-0419");
 script_bugtraq_id(2569);
 script_osvdb_id(10885);

 script_name(english:"Oracle Application Server ndwfn4.so HTTP Request Remote Overflow");
 script_summary(english:"Web server buffer overflow");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code may be run on the remote server.");
 script_set_attribute(attribute:"description", value:
"It may be possible to make a web server execute arbitrary code by
sending it a too long url starting with /jsp/ For example: GET
/jsp/AAAA.....AAAAA");
 script_set_attribute(attribute:"solution", value:"Contact your vendor for the latest software release.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/04/10");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/04/16");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_DESTRUCTIVE_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("http_version.nasl", "www_too_long_url.nasl");
 script_exclude_keys("www/too_long_url_crash");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www",80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

port = get_http_port(default:80);
if(!get_port_state(port))exit(0);
if(http_is_dead(port:port))exit(0);

r = http_send_recv3(port: port, method: 'GET', item: strcat("/jsp/", crap(2500)));
if (http_is_dead(port: port, retry: 3))
  security_hole(port);
