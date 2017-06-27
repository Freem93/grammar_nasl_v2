#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22416);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/10/13 15:19:32 $");

  script_name(english:"IBM DB2 Connection Port Detection");
  script_summary(english:"Detects a DB2 connection port.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an open connection port for an IBM DB2 instance.");
  script_set_attribute(attribute:"description", value:
"The remote host is running IBM DB2 with an open connection port for
a DB2 instance. IBM DB2 is a commercial database, and a connection
port is used by remote clients when connecting to a DB2 server
instance.");
  script_set_attribute(attribute:"see_also", value:"http://www.ibm.com/software/data/db2/");
  # http://pic.dhe.ibm.com/infocenter/db2luw/v10r1/index.jsp
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?3c362c6e");
  script_set_attribute(attribute:"solution", value:
"Limit incoming traffic to this port if desired.");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/09/21");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:db2");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Databases");

  script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");

  # MA 2007-03-11: I got a FP on port #53 in thorough_tests mode, but
  # was unable to reproduce it. Adding a dependency on dns_server should
  # fix it.
  script_dependencies("find_service1.nasl", "dns_server.nasl");
  script_require_ports("Services/unknown", 50000, 60000);

  exit(0);
}

include("audit.inc");
include("byte_func.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");

function make_request()
{
  # connect to a database named "nessus" + unixtime().
  return
    mkword(0x89) +                     # length (?)
    mkbyte(0xd0) +                     # type (?)
    raw_string(0x41, 0x00, 0x01, 0x00, 0x83, 0x10, 0x41) +     # ?
    mkword(0x39) +                     # length (?)
    mkbyte(0x11) +                     # type, 0x11 => string (?)
    ascii2ebcdic(
      str:";db2jcc_application  JCC020800.GA0A01CB" +
        raw_string(
          0x2e, 0x01, 0x0c, 0xe1, 0xe9, 0x3e, 0x9d, 0x00,
          0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        )
      ) +
    mkword(0x16) +                     # length (?)
    mkbyte(0x11) +                     # type, 0x11 => string (?)
    ascii2ebcdic(str:"_nessus" + unixtime() + "  ") +
    mkword(0x0c) +                     # length (?)
    mkbyte(0x11) +                     # type, 0x11 => string (?)
    ascii2ebcdic(str:"!JCC02080") +
    mkword(0x18) +                     # length (?)
    mkbyte(0x14) +                     # type (?)
    raw_string(
      0x04, 0x14, 0x03, 0x00, 0x07, 0x24, 0x07, 0x00,
      0x07, 0x24, 0x0f, 0x00, 0x07, 0x14, 0x40, 0x00,
      0x07, 0x14, 0x74, 0x00, 0x05
    ) +
    mkword(0x0c) +                     # length (?)
    mkbyte(0x11) +                     # type, 0x11 => string (?)
    ascii2ebcdic(str:raw_string(0xe5) + "QDB2/JVM") +
    mkword(0x26) +                     # length (?)
    mkbyte(0xd0) +                     # type (?)
    raw_string(
      0x01, 0x00, 0x02, 0x00, 0x20, 0x10, 0x6d, 0x00,
      0x06, 0x11, 0xa2, 0x00, 0x03, 0x00, 0x16, 0x21,
      0x10, 0xe2, 0xc1, 0xd4, 0xd7, 0xd3, 0xc5, 0x40,
      0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40, 0x40,
      0x40, 0x40, 0x40
    );
}

# There are two possible default ports DB2 might use.
ports = make_list(50000, 60000);

# If the "Perform thorough tests" setting is enabled, we want to search unknown services too.
if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
  ports = list_uniq(make_list(get_unknown_svc_list(), ports));

# For each of the ports we want to try, fork.
port = branch(ports);

if (!get_tcp_port_state(port))
  audit(AUDIT_PORT_CLOSED, port, "TCP", code:0);

soc = open_sock_tcp(port);
if (!soc)
  audit(AUDIT_SOCK_FAIL, port, "TCP");

req = make_request();
bytes_sent = send(socket:soc, data:req);
if (bytes_sent != strlen(req))
  exit(1, "Unable to deliver complete payload to service listening on port " + port + ".");

res = recv(socket:soc, min:4, length:2048);
close(soc);

if (!res)
  audit(AUDIT_RESP_NOT, port);

# Application information, should it be extractable.
app = NULL;

# Flags whether the host is running DB2 or not.
db2_detected = FALSE;

# If first record is of type 0xd0...
if (strlen(res) > 3 && getbyte(blob:res, pos:2) == 0xd0)
{
  # Extract it.
  len = getword(blob:res, pos:0);
  if (len > 0 && len <= strlen(res))
  {
    rec = substr(res, 0, len-1);

    # If it looks like a DB2 instance connection port...
    if (
      ascii2ebcdic(str:"QDB2/") >< rec &&
      ascii2ebcdic(str:"DB2CTLSV") >!< rec
    )
    {
      # Grab the application info.
      i = stridx(res, ascii2ebcdic(str:"QDB2/"));
      if (i > 0 && getbyte(blob:res, pos:i-2) == 0x11)
      {
        len = getword(blob:res, pos:i-4);
        if (len > 0) app = ebcdic2ascii(str:substr(res, i+1, i+len-4-1));

        j = stridx(res, ascii2ebcdic(str:"!SQL"));
        if (j > 0 && getbyte(blob:res, pos:j-1) == 0x11)
        {
          len = getword(blob:res, pos:j-3);
          if (len > 0)
          {
            ver = ebcdic2ascii(str:substr(res, j+4, j+len-3-1));
            app += " " +
              int(substr(ver, 0, 1)) + "." +
              int(substr(ver, 2, 3)) + "." +
              int(substr(ver, 4, 4));
          }
        }
      }

      db2_detected = TRUE;
    }
  }
}

if (!db2_detected)
  audit(AUDIT_RESP_BAD, port);

# Register and report the service.
register_service(port:port, ipproto:"tcp", proto:"db2c_db2");

report = NULL;
if (report_verbosity > 0 && !isnull(app))
  report = strcat('\nApplication : ', app, '\n');
security_note(port:port, extra:report);
