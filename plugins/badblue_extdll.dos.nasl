#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(17241);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2005-0595");
  script_bugtraq_id(12673);
  script_osvdb_id(14238);

  script_name(english:"BadBlue ext.dll mfcisapicommand Parameter Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to buffer overflow attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of BadBlue HTTP server that has a
buffer overflow vulnerability in 'ext.dll', a module that handles HTTP
requests.  An unauthenticated, remote attacker can leverage this
vulnerability by sending an HTTP request containing a
'mfcisapicommand' parameter with more than 250 chars to kill the web
server and possibly execute code remotely with Administrator rights." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Feb/671" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BadBlue 2.60.0 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'BadBlue 2.5 EXT.dll Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/01");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/02/25");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Detects MFCISAPICommand remote buffer overflow vulnerability in BadBlue");
  script_category(ACT_MIXED_ATTACK);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80, embedded: 0);

banner = get_http_banner(port:port);
if (!banner || "BadBlue/" >!< banner) exit(0);

if(safe_checks())
{
 vulnerable = egrep(pattern:"^Server: BadBlue/([0-1]\.|2\.[0-5][^0-9])", string:banner);
 if (vulnerable) security_hole(port);

 exit (0);
}
else {
 if (http_is_dead(port:port)) exit(0);

 # Send a malicious request.
req = string(
  "GET /ext.dll?mfcisapicommand=",
  crap(length:251, data:"A"),
  "&page=index.htx",
  "\r\n\r\n"
 );
r = http_send_recv_buf(port: port, data: req);

 # If the server's down, it's a problem.
 if (http_is_dead(port:port)) security_hole(port);
}
