#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(10273);
  script_version("$Revision: 1.30 $");

  script_name(english:"Samba Web Administration Tool (SWAT) Detection");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web server for Samba administration." );
 script_set_attribute(attribute:"description", value:
"The remote host is running SWAT, the Samba Web Administration Tool.

SWAT is a web-based configuration tool for Samba administration that
also allows for network-wide MS Windows network password management." );
 script_set_attribute(attribute:"see_also", value:"http://www.samba.org/samba/docs/man/Samba-HOWTO-Collection/SWAT.html" );
 script_set_attribute(attribute:"solution", value:
"Either disable SWAT or limit access to authorized users and ensure that
it is set up with stunnel to encrypt network traffic." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/03/03");
 script_cvs_date("$Date: 2011/03/14 21:48:13 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
  summary["english"] = "Detects a SWAT Server";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2000-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/swat", "Services/www", 901);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


# Fire on any ports that find_services already identified as running SWAT.
port901 = 0;
foreach port (get_kb_list("Services/swat")) {
  if (port == 901) port901 = 1;
  if (get_port_state(port)) {
    security_note(port);
  }
}


# Explicitly test various ports.
if (thorough_tests) {
  if (port901) ports = get_kb_list("Services/www");
  else ports = add_port_in_list(list:get_kb_list("Services/www"), port:901);
}
else {
  if (port901) ports = make_list();
  else ports = make_list(901);
}
if (! isnull(ports)) {
  foreach port (ports) {
    if ( ! get_port_state(port) ) continue;
    # Try to pull up the initial page.
    w = http_send_recv3(method:"GET", item:"/", port:port);
    if (isnull(w)) exit(1, "the web server did not answer");

    # SWAT's running if we're prompted to authenticated to the SWAT realm.
    if ('WWW-Authenticate: Basic realm="SWAT"' >< w[1]) {
      security_note(port);
    }
    # else SWAT's running in demo mode if we get to the initial page.
    else if (
      '<TITLE>Samba Web Administration Tool</TITLE>' >< w[2] &&
      '<IMG SRC="/swat/images/samba.gif" ALT="[ Samba ]" border=0>' >< w[2]
    ) 
    {
     set_kb_item(name:"SWAT/no_auth", value:port);
     security_note(port);
    }
  }
}
