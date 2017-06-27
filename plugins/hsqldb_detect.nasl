#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20065);
  script_version("$Revision: 1.11 $");

  script_name(english:"HSQLDB Server Detection");
  script_summary(english:"Detects an HSQLDB server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a database server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running HSQLDB, an open source database written in
Java, and its database engine is listening on TCP port 9001 for
network server database connections using JDBC." );
 script_set_attribute(attribute:"see_also", value:"http://hsqldb.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/10/20");
 script_cvs_date("$Date: 2013/01/07 23:25:52 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"x-cpe:/a:hsqldb:hsqldb");
script_end_attributes();


  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");

  script_require_ports("Services/unknown", 9001);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");


if (thorough_tests && ! get_kb_item("global_settings/disable_service_discovery")  ) {
  port = get_unknown_svc(9001);
  if (!port) exit(0);
}
else port = 9001;
if (!get_tcp_port_state(port)) exit(0);


# Try to login.
soc = open_sock_tcp(port);
if (!soc) exit(0);

user = toupper("sa");                   # default username
pass = toupper("");                     # default password
db = "";
req = raw_string(
                                        # packet size, to be added later
  0x00, 0x01, 0x00, 0x07,               # ???, perhaps a version number
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, 0x00,               # ???
  0x00, 0x00, 0x00, strlen(user), user, # user
  0x00, 0x00, 0x00, strlen(pass), pass, # pass
  0x00, 0x00, 0x00, strlen(db), db,     # database name
  0x00, 0x00, 0x00, 0x00                # ???
);
req = raw_string(
  0x00, 0x00, 0x00, (strlen(req)+4),    # packet size, as promised
  req
);
send(socket:soc, data:req);


# Read the response.
res = recv(socket:soc, length:64);
if (res == NULL) exit(0);


# If it looks like an HSQLDB server because...
if (
  # we got in or ...
  (
    strlen(res) == 20 && 
    raw_string(
      0x00, 0x00, 0x00, 0x14, 
      0x00, 0x00, 0x00, 0x01, 
      0x00, 0x00, 0x00, 0x00
    ) >< res
  ) ||
  # the user name is invalid or ...
  string("User not found: ", user) >< res ||
  # the password is invalid or ...
  "Access is denied" >< res ||
  # the DB is invalid
  string("Database does not exists in statement [", db, "]") >< res
) {
  # Register and report the service.
  register_service(port:port, ipproto:"tcp", proto:"hsqldb");

  security_note(port);
}
