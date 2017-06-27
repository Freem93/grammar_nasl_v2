#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22410);
  script_version("$Revision: 1.13 $");

  script_name(english:"Derby Network Server Detection");
  script_summary(english:"Detects a Derby Network Server");

  script_set_attribute(attribute:"synopsis", value:
"A Derby Network Server is listening on the remote host." );
  script_set_attribute(attribute:"description", value:
"The remote host is running a Derby (formerly Cloudscape) Network
Server, which allows for network access to the Derby database engine
on that host.  Derby itself is a Java-based relational database
developed by the Apache Software Foundation." );
  script_set_attribute(attribute:"see_also", value:"http://db.apache.org/derby/" );
  script_set_attribute(attribute:"see_also", value:"https://en.wikipedia.org/wiki/Apache_Derby" );
  script_set_attribute(attribute:"risk_factor", value:"None" );
  script_set_attribute(attribute:"solution", value:"n/a" );
  script_set_attribute(attribute:"plugin_publication_date", value: "2006/09/18");
  script_cvs_date("$Date: 2017/05/16 19:35:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2017 Tenable Network Security, Inc.");

  script_dependencies("find_service1.nasl");
  script_require_ports("Services/unknown", 1527);

  exit(0);
}

include("byte_func.inc");
include("charset_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && !get_kb_item("global_settings/disable_service_discovery"))
{
  port = get_unknown_svc(1527);
  if (!port) exit(0, "There are no unknown services.");
}
else port = 1527;
if (known_service(port:port)) exit(0, "The service is already known on port "+port+".");
if (!get_tcp_port_state(port)) exit(0, "Port "+port+" is not open.");

code_points = make_array(
  "ACCSEC", 0x106D,
  "ACCSECRD", 0x14AC,
  "EXCSAT", 0x1041,
  "EXCSATRD", 0x1443,
  "EXTNAM", 0x115E,
  "MGRLVLLS", 0x1404,
  "RDBNAM", 0x2110,
  "SECMEC", 0x11A2,
  "SRVCLSNM", 0x1147,
  "SRVNAM", 0x116D,
  "SRVRLSLV", 0x115A
);

function drda_find_param(blob, code_point, dont_convert)
{
  local_var length, rec;

  # Skip over record header to parameters.
  if (strlen(blob) < 10) return NULL;

  blob = substr(blob, 10);
  while (strlen(blob))
  {
    # Ensure that the parameter is long enough.
    if (strlen(blob) < 4)
    {
      # exit(1, "Record parameter from port " + port + " is too short to contain header.");
      return NULL;
    }
    length = getword(blob:blob, pos:0);
    if (strlen(blob) < length)
    {
      #exit(1, "Record parameter from port " + port + " is shorter than its declared length.");
      return NULL;
    }

    # Check whether this parameter is the one we're looking for.
    if (getword(blob:blob, pos:2) == code_points[code_point])
    {
      rec = substr(blob, 4, length - 1);
      if (!dont_convert) rec = ebcdic2ascii(str:rec);
      return rec;
    }

    # Remove current parameter from blob.
    blob = substr(blob, length);
  }

  return NULL;
}

function drda_find_record(blob, code_point)
{
  local_var length;

  while (strlen(blob))
  {
    # Ensure that the record is long enough.
    if (strlen(blob) < 6)
    {
      # exit(1, "DRDA record from port " + port + " is too short to contain header.");
      return NULL;
    }
    length = getword(blob:blob, pos:0);
    if (strlen(blob) < length)
    {
      # exit(1, "DRDA record from port " + port + " is shorter than its declared length.");
      return NULL;
    }

    # Check whether this record is the one we're looking for.
    if (getword(blob:blob, pos:8) == code_points[code_point])
      return substr(blob, 0, length - 1);

    # Remove current record from blob.
    blob = substr(blob, length);
  }

  return NULL;
}

function drda_make_param(code_point, data, dont_convert)
{
  local_var length, param;

  if (!dont_convert)
    data = ascii2ebcdic(str:data);

  param = mkword(code_points[code_point]) + data;
  length = mkword(2 + strlen(param));

  return length + param;
}

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

# All parameters in DRDA are big-endian.
set_byte_order(BYTE_ORDER_BIG_ENDIAN);

# Create parameters for the first chunk.
chunk1 = "";
chunk1 += drda_make_param(code_point:"EXTNAM", data:"derbydncmain");
chunk1 += drda_make_param(code_point:"SRVNAM", data:"Derby");
chunk1 += drda_make_param(code_point:"SRVRLSLV", data:"Nessus");
chunk1 += drda_make_param(
  code_point:"MGRLVLLS",
  data:raw_string(
    0x14, 0x03, 0x00, 0x07,
    0x24, 0x07, 0x00, 0x07,
    0x24, 0x0f, 0x00, 0x07,
    0x14, 0x40, 0x00, 0x07
  ),
  dont_convert:TRUE
);
chunk1 += drda_make_param(code_point:"SRVCLSNM", data:"QDERBY/JVM");

# Create header for the first chunk.
head1 = "";
head1 += mkword(10 + strlen(chunk1));
head1 += mkbyte(0xD0);
head1 += mkbyte(0x41);
head1 += mkword(0x01);
head1 += mkword(4 + strlen(chunk1));
head1 += mkword(code_points["EXCSAT"]);

# Create parameters for the second chunk.
chunk2 = "";
chunk2 += drda_make_param(
  code_point:"SECMEC",
  data:raw_string(0x00, 0x04),
  dont_convert:TRUE
);
chunk2 += drda_make_param(code_point:"RDBNAM", data:"nessus");

# Create header for the first chunk.
head2 = "";
head2 += mkword(10 + strlen(chunk2));
head2 += mkbyte(0xD0);
head2 += mkbyte(0x01);
head2 += mkword(0x02);
head2 += mkword(4 + strlen(chunk2));
head2 += mkword(code_points["ACCSEC"]);

# Put all the pieces together.
req = head1 + chunk1 + head2 + chunk2;

# Probe the service.
send(socket:soc, data:req);
res = recv(socket:soc, length:4096);
if (strlen(res) == 0) exit(0, "The service on port "+port+" failed to respond.");
if (strlen(res) < 10) exit(0, "The response from port "+port+" is too short.");


# Find the record containing Server Attributes Reply Data.
rec = drda_find_record(blob:res, code_point:"EXCSATRD");
if (isnull(rec))
  exit(0, "The response from port " + port + " doesn't contain record with server attribute information.");

# Ensure that this is actually an Apache Derby installation.
software = drda_find_param(blob:rec, code_point:"SRVCLSNM");
if (isnull(software))
  exit(0, "The response from port " + port + " doesn't contain parameter with software name information.");
if (software != "Apache Derby")
  exit(0, software + " is running on port " + port + ", not Apache Derby.");
register_service(port:port, ipproto:"tcp", proto:"derby");

# Parse out the version information.
version = drda_find_param(blob:rec, code_point:"SRVRLSLV");
if (!isnull(version))
{
  version = ereg_replace(pattern:"^[A-Z]+[0-9]+/([.0-9]+) - \([0-9]+\)$", replace:"\1", string:version);
  set_kb_item(name:"derby/"+port+"/version", value:version);
  if (report_verbosity > 0)
  {
    report = '\n  Version : ' + version + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
  exit(0);
}
else security_note(port);
