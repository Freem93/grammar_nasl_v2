#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40885);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2009-2346");
  script_bugtraq_id(36275);
  script_osvdb_id(57762);
  script_xref(name:"EDB-ID", value:"8940");
  script_xref(name:"Secunia", value:"36593");

  script_name(english:"Asterisk IAX2 Call Number Exhaustion DoS");
  script_summary(english:"Examines the IAX2 response");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote VoIP service is susceptible to a denial of service attack."
  );
  script_set_attribute(attribute:"description", value:
"The version of Asterisk running on the remote host appears to be using
an older implementation of the IAX2 protocol that does not support
call token validation.  Due to a design flaw in the protocol, a remote
attacker could send a large number of messages, exhausting all
available call numbers in the process.  This would result in a denial
of service to legitimate users."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://downloads.asterisk.org/pub/security/AST-2009-006.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.securityfocus.com/archive/1/archive/1/506257/100/0/threaded"
  );
  script_set_attribute(attribute:"solution", value:
"Upgrade to the relevant version of Asterisk referenced in the
vendor's advisory."  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/06/12"   # Date the DoS code was posted to milw0rm
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/09/03"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/09/08"
  );
 script_cvs_date("$Date: 2016/11/15 13:39:08 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:asterisk:open_source");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Denial of Service");

  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

  script_dependencies("iax2_detection.nasl");
  script_require_keys("Services/udp/iax2");
  script_require_udp_ports(4569);

  exit(0);
}

include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");


port = get_kb_item("Services/udp/iax2");
if (!port) port = 4569;
if (! get_udp_port_state(port)) exit(0, "UDP port "+port+" is not open.");

soc = open_sock_udp(port);
if (!soc) exit(1, "Unable to create socket.");

# Generate the IAX2 'NEW' packet.
iax_new = string(
  mkword(0x8001),    # 'F' bit + source call number
  mkword(0),         # 'R' bit + dest call number
  mkdword(0),        # timestamp
  mkbyte(0),         # OSeqno
  mkbyte(0),         # ISeqno
  mkbyte(6),         # frametype, 6 => IAX frame
  mkbyte(0x01)       # 'C' bit + subclass, 0x01 => NEW request
);

send(socket:soc, data:iax_new);
res = recv(socket:soc, length:128);
if (isnull(res)) exit(1, "The server failed to respond.");

# Check if we get the right response. 
if (strlen(res) < 12) exit(1, "Unexpected response received.");
subclass = getbyte(blob:res, pos:11);

# This issue was fixed by changing the protocol, which we can detect in the
# response.  INVAL (0x0a) = vulnerable, REJECT (0x06) = patched 
if (subclass == 0x0a)
  security_warning(port:port, proto:"udp");
else if (subclass == 0x06)
  exit(0, "The host is not affected.");
else
  exit(1, "Unexpected IAX subclass received (" + subclass + ").");

