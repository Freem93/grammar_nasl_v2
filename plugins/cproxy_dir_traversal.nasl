#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description) {
  script_id(17273);
  script_version("$Revision: 1.10 $");

  script_cve_id("CVE-2005-0657");
  script_bugtraq_id(12722);
  script_osvdb_id(14358, 14359);

  script_name(english:"CProxy 3.3.x - 3.4.4 Multiple Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote HTTP proxy server is affected by multiple issues." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of Computalynx's CProxy Server
that suffers from the following vulnerabilities:

  - Arbitrary Local File Access
    CProxy allows an attacker to retrieve arbitrary local files
    by issuing an HTTP request with directory traversal sequences
    relative to a subdirectory under CProxy's cache/intracache
    directory. This may lead to the disclosure of sensitive 
    information.

  - Denial of Service Vulnerability
    An attacker may crash the proxy while requesting arbitrary
    local files, either by requesting an executable file or by
    using a GET (as opposed to HEAD or POST) request." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/lists/bugtraq/2005/Mar/0068.html" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/03");
 script_cvs_date("$Date: 2011/03/11 21:52:31 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Detects directory traversal file access and DoS vulnerability in CProxy");
  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_dependencies("proxy_use.nasl");
  script_require_keys("Proxy/usage");
  script_require_ports("Services/http_proxy", 3128, 8080);

  exit(0);
}


port = get_kb_item("Services/http_proxy");
if (!port) {
  if (get_port_state(8080)) port = 8080;
  else port = 3128;
}
if (!get_port_state(port)) exit(0);
usable_proxy = get_kb_item("Proxy/usage");
if (!usable_proxy) exit(0);


# Make sure it's CProxy by requesting one of its page templates.
soc = open_sock_tcp(port);
if (!soc) exit(0);
req = string("GET http://proxyforms/proxylogin.html HTTP/1.0\r\nHost: proxyforms\r\n\r\n");
send(socket:soc, data:req);
buf = recv(socket:soc, length:4096);
close(soc);
if (
  (buf =~ "<title>CProxy Server") ||
  (buf =~ "Welcome to CProxy Server")
) {
  # Request CProxy's readme using a HEAD request to avoid crashing the service.
  soc = open_sock_tcp(port);
  if (!soc) exit(0);
  # nb: this assumes the user hasn't moved CProxy's cache from its 
  #     default location.
  #
  # nb: Kristof Philipsen's advisory doesn't use a Host header, but in
  #     testing on Win98 and WinME, the proxy would return the contents 
  #     of the requested file and then hang (not crash) consistently
  #     without it regardless of the request method or file type.
  req = string("HEAD http://../../Readme.txt HTTP/1.0\r\nHost: proxyforms\r\n\r\n");
  send(socket:soc, data:req);
  buf = recv(socket:soc, length:4096);
  close(soc);

  # If we got it, there's a problem.
  if (buf =~ "Computalynx CProxy Server") {
    security_hole(port);
  }
}
