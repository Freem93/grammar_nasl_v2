#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21243);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2011/11/15 01:21:55 $");

  script_cve_id("CVE-2006-0992");
  script_bugtraq_id (17503);
  script_osvdb_id(24617);

  script_name(english:"Novell GroupWise Messenger Accept Language Remote Overflow");
  script_summary(english:"Checks for Novell Messenger Messaging Agent Buffer overflow");
 
  script_set_attribute(attribute:"synopsis", value:
"It is possible to execute code on the remote web server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Novell Messenger Messaging Agent, an
enterprise instant messaging server for Windows, Linux, and Netware. 

This version of this service is running an HTTP server which is
vulnerable to a stack overflow. 

An attacker can exploit this vulnerability to execute code on the
remote host.");
  script_set_attribute(attribute:"see_also", value:"http://www.zerodayinitiative.com/advisories/ZDI-06-008/");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Groupwise Messenger 2.0.1 beta3 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Novell Messenger Server 2.0 Accept-Language Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/04/13");
  script_set_attribute(attribute:"patch_publication_date", value:"2006/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Gain a shell remotely");
  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencie("nmma_detection.nasl");
  script_exclude_keys('Settings/disable_cgi_scanning');
  script_require_ports("Services/www", 8300);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8300); 
if (!get_kb_item("Novell/NMMA/" + port)) exit(0, "Novell NMMA was not detected on port "+port+".");

# getlocation command was not in 2.0.0
data = string ("GET /getlocation HTTP/1.0\r\n\r\n");
w = http_send_recv_buf(port: port, data: data, exit_on_fail:TRUE);
buf = strcat(w[0], w[1], '\r\n', w[2]);

# patched version replies with the download page

if (egrep (pattern:"^HTTP/1.0 200", string:buf) && ("NM_A_SZ_RESULT_CODE" >!< buf))
  security_hole(port);
