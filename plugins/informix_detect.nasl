#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
  script_id(22228);
  script_version("$Revision: 1.10 $");

  script_name(english:"Informix Detection");
  script_summary(english:"Detects Informix");

 script_set_attribute(attribute:"synopsis", value:
"An Informix server is listening on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Informix, an online transaction processing
(OLTP) data server from IBM." );
 script_set_attribute(attribute:"see_also", value:"http://www-306.ibm.com/software/data/informix/" );
 script_set_attribute(attribute:"risk_factor", value:
"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/08/16");
 script_cvs_date("$Date: 2011/07/28 11:44:54 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("find_service2.nasl");
  script_require_ports("Services/unknown", 9088, 1526);

  exit(0);
}


include("byte_func.inc");
include("global_settings.inc");
include("misc_func.inc");

if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery") ) 
{
  ports = add_port_in_list(list:get_kb_list("Services/unknown"), port:1526);
}
else ports = make_list(1526);

# Versions 11 and greater use a new default port
ports = add_port_in_list(list:ports, port:9088);

foreach port (ports)
{
  if (! service_is_unknown(port:port)) continue;
  if (!get_tcp_port_state(port)) continue;
soc = open_sock_tcp(port);
  if (!soc)
    continue;

user = "nessus";
pass = SCRIPT_NAME;
db = "sysmaster";
dbpath = "ol_nessus";
zero = raw_string(0x00);


# Attempt a login.
req = raw_string(
  "sq",                                # header
  crap(8),                             # length + constant (to be filled in later)
  "sqlexec ",                          # magic
  user, " -p", pass, " ",              # credentials
  "9.22.TC1   ",                       # client version
  "RDS#N000000 ",                      # RDS
  "-d", db, " ",                       # database
  "-fIEEEI ",                          # IEEE
  "DBPATH=//", dbpath, " ",            # dbpath
  #"DBMONEY=$. ",                       # dbmoney
  "CLIENT_LOCALE=en_US.CP1252 ",       # client locale
  #"CLNT_PAM_CAPABLE=1 ",               # client pam capable
  "DB_LOCALE=en_US.819 ",              # db locale
  ":", 
  "AG0AAAA9b3IAAAAAAAAAAAA9c29jdGNwAAAAAAABAAABMQAAAAAAAAAAc3FsZXh",
  "lYwAAAAAAAAVzcWxpAAACAAAAAwAKb2xfbmVzc3VzAABrAAAAAAAAnmUAAAAAAA",
  "duZXNzdXMAAAduZXNzdXMAAC1DOlxQcm9ncmFtIEZpbGVzXE5lc3N1c1xpbmZvc",
  "m1peF9kZXRlY3QubmFzbAAAdAAIAAAE0gAAAAAAfwo="
);
req = insstr(req, base64(str:raw_string(mkword(strlen(req)-4), 0x01, 0x3d, zero, zero)), 2, 9);

max_tries = 5;
for (try=0; try<max_tries; try++)
{
  send(socket:soc, data:req);
  res = recv(socket:soc, length:2048);
  if (strlen(res)) break;
}
close(soc);


# If ...
if (
  # the first word is the length of the result and...
  strlen(res) > 2 && 
  strlen(res) == getword(blob:res, pos:0) &&
  # it looks like Informix
  substr(res, 16, 31) == raw_string("IEEEI", 0x00, 0x00, "lsrvinfx", 0x00)
)
{
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"informix");

  # Try to extract some interesting info.
  info = "";
  # nb: version and serial number are returned only w/ valid credentials.
  #     Also, note that the reported version number is not necessarily 
  #     the real product version number; eg, for 10.0 TC3, 9.50.TC3.TL 
  #     is reported.
  if ("Version " >< res)
  {
    version = strstr(res, "Version ") - "Version ";
    if (version) version = version - strstr(version, zero);
    if (version) info += "  Version :           " + version + '\n';
  }
  if ("Serial Number " >< res)
  {
    serial = strstr(res, "Serial Number ") - "Serial Number ";
    if (serial) serial = serial - strstr(serial, zero);
    if (serial) info += "  Serial Number :     " + serial + '\n';
  }
  contents = strstr(res, raw_string(zero, "k", zero));
  pos = 15;
  if (contents && strlen(contents) > pos)
  {
    len = getbyte(blob:contents, pos:pos);
    host = substr(contents, pos+1, pos+1+len-2);
    if (host =~ "^[a-zA-Z0-9]") info += "  Host Name :         " + host + '\n';

    pos += len + 2;
    if (strlen(contents) > pos)
    {
      len = getbyte(blob:contents, pos:pos);
      # seems to be the same as the previous field, perhaps w/ a change of case.
    }

    pos += len + 2;
    if (strlen(contents) > pos)
    {
      len = getbyte(blob:contents, pos:pos);
      path = substr(contents, pos+1, pos+1+len-2);
      if (path =~ "^[/a-zA-Z0-9]") info += "  Installation Path : " + path + '\n';
    }
  }
  security_note(port:port, extra: info);
}
}
