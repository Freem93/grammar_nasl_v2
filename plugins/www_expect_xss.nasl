#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22254);
  script_version("$Revision: 1.27 $");
  script_cvs_date("$Date: 2016/11/01 19:59:57 $");

  script_cve_id("CVE-2006-3918", "CVE-2007-5944");
  script_bugtraq_id(19661, 26457);
  script_osvdb_id(27487, 27488, 38700, 72887);

  script_name(english:"Web Server Expect Header XSS");
  script_summary(english:"Checks for an XSS flaw involving Expect Headers");

  script_set_attribute(attribute:"synopsis", value:
"The remote web server is vulnerable to a cross-site scripting attack.");
  script_set_attribute(attribute:"description", value:
"The remote web server fails to sanitize the contents of an 'Expect'
request header before using it to generate dynamic web content.  An
unauthenticated, remote attacker may be able to leverage this issue to
launch cross-site scripting attacks against the affected service,
perhaps through specially crafted ShockWave (SWF) files.");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/May/150");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/May/440");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2006/Jul/423");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.2");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_2.0");
  script_set_attribute(attribute:"see_also", value:"http://www.apache.org/dist/httpd/CHANGES_1.3");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1PK24631");
  script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg24017314");
  script_set_attribute(attribute:"solution", value:
"Check with the vendor for an update to the web server.  For Apache,
the issue is reportedly fixed by versions 1.3.35 / 2.0.57 / 2.2.2; for
IBM HTTP Server, upgrade to 6.0.2.13 / 6.1.0.1; for IBM WebSphere
Application Server, upgrade to 5.1.1.17.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/08/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses : XSS");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl", "http_version.nasl");
  script_require_ports("Services/www", 80);

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("raw.inc");

if (islocalhost() ) exit(0, "Nessus can not test for the issue over the loopback interface.");

port = get_http_port(default:80);
if ( get_port_transport(port) != ENCAPS_IP ) exit(0, "This script only works for HTTP connections");

soc = open_sock_tcp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port);


# Generate a request to exploit the flaw.
exploit = string(SCRIPT_NAME, " testing for BID 19661 <test>");
rq = http_mk_get_req(port: port, item: "/", add_headers: make_array("Expect", exploit));
buf = http_mk_buffer_from_req(req: rq);
if ( buf == NULL ) audit(AUDIT_FN_FAIL, "http_mk_buffer_from_req");

# Send the request but don't worry about the response.
filter = string(
  "tcp and ",
  "src host ", get_host_ip(), " and ",
  "src port ", port, " and ",
  "dst port ", get_source_port(soc)
);
res = send_capture(socket:soc, data:buf, pcap_filter:filter);
if (res == NULL) audit(AUDIT_RESP_NOT, port);
flags = get_tcp_element(tcp:res, element:"th_flags");
if (flags & TH_ACK == 0) exit(0, "The TCP response from the web server on port "+port+" was not an ACK.");


# Half-close the connection.
#
# nb: the server sends a 417 response only after the connection is
#     closed; a half-close allows us to receive the response.
ip = ip();
seq = get_tcp_element(tcp:res, element:"th_ack");
tcp = tcp(
  th_dport : port,
  th_sport : get_source_port(soc),
  th_seq   : seq,
  th_ack   : seq,
  th_win   : get_tcp_element(tcp:res, element:"th_win"),
  th_flags : TH_FIN|TH_ACK
);
halfclose = mkpacket(ip, tcp);
r = send_packet(halfclose, pcap_filter:filter, pcap_timeout:5);
if ( !isnull(r) && ("417 Expectation Failed" >< r ||
		    "417 invalid Expect header value:" >< r ) )
{
 res2 = strstr(r, "417 Expectation Failed");
 if ( isnull(res2) ) res2 = strstr(r, "417 invalid Expect header value:");
}


# There's a problem if we see our exploit in the response.
res = recv(socket:soc, length:1024);
close(soc);

if ( isnull(res)) res = res2;

if (
  res &&
  (
    "417 Expectation Failed" >< res ||
    "417 invalid Expect header value:" >< res
  ) &&
  exploit >< res
)
{
  set_kb_item(name:'www/'+port+'/XSS', value:TRUE);

  if (report_verbosity > 0)
  {
    report = strcat(
      '\n',
      'Nessus was able to exploit the issue using the following request :\n',
      '\n',
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), '\n',
      http_mk_buffer_from_req(req:rq),
      crap(data:"-", length:30), " snip ", crap(data:"-", length:30), '\n'
    );
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else audit(AUDIT_HOST_NOT, 'affected');
