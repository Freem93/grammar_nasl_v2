#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21632);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id("CVE-2006-1516");
  script_bugtraq_id(17780);
  script_osvdb_id(25226);

  script_name(english:"MySQL Anonymous Login Handshake Remote Information Disclosure");
  script_summary(english:"Checks for anonymous login handshake info leakage in MySQL");

  script_set_attribute(attribute:"synopsis", value:
"The remote database server is affected by an information disclosure
flaw.");
  script_set_attribute(attribute:"description", value:
"The MySQL database server on the remote host reads from uninitialized
memory when processing a specially crafted login packet.  An
unauthenticated attacker may be able to exploit this flaw to obtain
sensitive information from the affected host as returned in an error
packet.");
  script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/432733/30/0/threaded");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-0-27.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/4.1/en/news-4-1-19.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.0/en/news-5-0-21.html");
  script_set_attribute(attribute:"see_also", value:"http://dev.mysql.com/doc/refman/5.1/en/news-5-1-10.html");
  script_set_attribute(attribute:"solution", value:"Upgrade to MySQL 4.0.27 / 4.1.19 / 5.0.21 / 5.1.10 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/06/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/02");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mysql:mysql");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/mysql", 3306);

  exit(0);
}


include("dump.inc");
include("global_settings.inc");
include("misc_func.inc");
include("mysql_func.inc");


port = get_service(svc:"mysql", default:3306, exit_on_fail:TRUE);

# Establish a connection.
#
# nb: this requires that the nessusd host be allowed to connect.
mysql_init(port:port, nocache:TRUE, exit_on_fail:TRUE);

# Send a malicious client authentication packet.
add_caps = CLIENT_LONG_PASSWORD | CLIENT_CONNECT_WITH_DB | CLIENT_PROTOCOL_41;
cap = mkdword(mysql_get_caps() | add_caps) +     # client capabilities
                                                 #   1 => long password
                                                 #   8 => specify db on connect
                                                 #   512 => 4.1 protocol
  mkdword(65535) +                               # max packet size
  mkbyte(mysql_get_lang()) +                     # charset
  crap(data:raw_string(0), length:23) +          # filler
  "nessus" +                                     # username minus null byte
  mkbyte(20) + crap(20) +                        # scramble (len + data)
  SCRIPT_NAME + crap(20) + mkbyte(0);            # database plus null byte
mysql_send_packet(data:cap);
pkt = mysql_recv_packet();
if (!isnull(pkt))
{
  err = mysql_parse_error_packet(packet:pkt);
  # nb: a non-affected version will report "Bad handshake".
  if (
    !isnull(err) && 
    (
      "Access denied" >< err["msg"] || 
      "Incorrect database name" >< err["msg"]
    )
  )
  {
    if (report_verbosity > 1)
    {
      msg = hexdump(ddata:err["msg"]);
      report = '\nHere is the text returned by the affected MySQL server :\n\n  '+msg+'\n';
    }
    else
      report = NULL;
    security_warning(port:port, extra:report);
    mysql_close();
    exit(0);
  }
}
mysql_close();

exit(0, 'The MySQL server on port '+port+' is not affected.');
