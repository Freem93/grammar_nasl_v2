#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32132);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/11/11 20:08:42 $");

  script_cve_id("CVE-2008-1897", "CVE-2008-1923");
  script_bugtraq_id(28901);
  script_osvdb_id(44648, 44649);
  script_xref(name:"Secunia", value:"29927");

  script_name(english:"Asterisk IAX2 Multiple Method Handshake Spoofing DoS");
  script_summary(english:"Performs an IAX2 handshake");

  script_set_attribute(attribute:"synopsis", value:
"The remote VoIP service can be abused to conduct an amplification
attack against third-party hosts.");
  script_set_attribute(attribute:"description", value:
"The version of Asterisk running on the remote host does not properly
validate an IAX2 handshake.  By spoofing NEW and ACK messages, an
unauthenticated, remote attacker may be able to leverage this issue to
flood a third-party host with packets from the affected host containing
audio data.");
  script_set_attribute(attribute:"see_also", value:"https://www.altsci.com/concepts/page.php?s=asteri&p=2");
  script_set_attribute(attribute:"see_also", value:"http://bugs.digium.com/view.php?id=10078");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2008/Apr/252");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Asterisk 1.4.20 / 1.2.28, Asterisk Business Edition C.1.8.1
/ B.2.5.2, AsteriskNOW 1.0.3, s800i (Asterisk Appliance) 1.1.0.3 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(16, 287);

  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2008/04/22");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:asterisk:open_source");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");

  script_dependencies("iax2_detection.nasl");
  script_require_keys("Services/udp/iax2");

  exit(0);
}


include("audit.inc");
include("byte_func.inc");


port = get_kb_item("Services/udp/iax2");
if (!port) port = 4569;
if (!get_udp_port_state(port)) audit(AUDIT_PORT_CLOSED, port, "UDP");

soc = open_sock_udp(port);
if (!soc) audit(AUDIT_SOCK_FAIL, port, "UDP");


src_call = rand() % 0xff;
start = unixtime();


# Send a NEW request and read the response.
new =
  mkword((1 << 15) | src_call) +       # 'F' bit + source call number
  mkword(0) +                          # 'R' bit + dest call number
  mkdword(0) +                         # timestamp
  mkbyte(0) +                          # OSeqno
  mkbyte(0) +                          # ISeqno
  mkbyte(6) +                          # frametype, 6 => IAX frame
  mkbyte(1) +                          # 'C' bit + subclass, 0x01 => NEW request
    mkbyte(8) +                        #   CODEC capability
      mkbyte(4) +                      #     length
      mkdword(0x2aa);
send(socket:soc, data:new);
res = recv(socket:soc, length:128);
if (strlen(res) == 0) exit(0);


# If we get an ACCEPT...
if (
  getword(blob:res, pos:0) > 0x8000 &&
  getword(blob:res, pos:2) & 0x7fff == src_call &&
  getbyte(blob:res, pos:10) == 6 &&
  getbyte(blob:res, pos:11) == 7
)
{
  # Calculate a destination callid different from what the remote sent us.
  callid = getword(blob:res, pos:0) ^ 0x8000;
  if (callid < 0x7f00) dst_call = callid + (rand() % 0xff);
  else dst_call = callid - (rand() % 0xff);

  # Send an ACK.
  ts = now - unixtime();
  ack =
    mkword((1 << 15) | src_call) +     # 'F' bit + source call number
    mkword(dst_call) +                 # 'R' bit + dest call number
    mkdword(ts) +                      # timestamp
    mkbyte(0) +                        # OSeqno
    mkbyte(0) +                        # ISeqno
    mkbyte(6) +                        # frametype, 6 => IAX frame
    mkbyte(4);                         # 'C' bit + subclass, 4 => ACK
  send(socket:soc, data:ack);
  res = recv(socket:soc, length:128);
  if (strlen(res) == 0) exit(0);

  # There's a problem if we get a control response.
  #
  # nb: a non-vulnerable implementation will respond with an INVAL.
  if (
    getword(blob:res, pos:0) > 0x8000 &&
    getword(blob:res, pos:2) == src_call &&
    getbyte(blob:res, pos:10) == 4
  )
  {
    security_warning(port:port, proto:"udp");
  }
}
