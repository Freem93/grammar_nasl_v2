#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(31642);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2007-6682");
  script_bugtraq_id(27015);
  script_osvdb_id(42208);

  script_name(english:"VLC Media Player network/httpd.c httpd_FileCallBack Function Connection Parameter Format String");
  script_summary(english:"Checks for a format string issue in the VLC server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote VLC web server is affected by a format string
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running VLC, a popular media player application
which can have an embedded web server. 

The remote version of this software is vulnerable to a format string
attack when processing a malformed 'Connection:' http header. 

An attacker can exploit this flaw to execute arbitrary commands with
the privileges of the VLC application." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to VLC 0.8.6e or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/03/21");
 script_cvs_date("$Date: 2011/04/13 17:51:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:videolan:vlc_media_player");
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2008-2011 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080, embedded: 1);

page = http_get_cache(port:port, item:"/", exit_on_fail: 1);
if ( ! egrep(pattern:"Copyright \(C\) .*the VideoLAN team", string:page, icase:TRUE) ) exit(0);
req = 'GET / HTTP/1.0\r\n' + 'Connection: YY%xZZ\r\n\r\n';
r = http_send_recv_buf(port: port, data: req, exit_on_fail: 1);
if ( egrep(pattern:"^Connection: *YY[0-9a-fA-F]+ZZ", string:r[1]) ) security_hole(port);
