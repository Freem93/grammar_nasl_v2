#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(21241);
  script_version("$Revision: 1.9 $");

  script_name(english:"Novell Messenger Archive Agent Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an instant messaging server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell Messenger Archive Agent,
an enterprise instant messaging server for Windows, Linux, and
NetWare." );
 script_set_attribute(attribute:"solution", value:
"If you do not use this software, disable it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/04/19");
 script_cvs_date("$Date: 2011/03/14 21:48:08 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  summary["english"] = "Checks for Novell Messenger Archive Agent";
  script_summary(english:summary["english"]);
 
  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_require_ports("Services/www", 8310);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8310);

data = string ("GET /logout HTTP/1.0\r\n\r\n");
w = http_send_recv_buf(port: port, data: data);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
buf = strcat(w[0], w[1], '\r\n', w[2]);

if ( 
     ("HTTP/1.0 200" >< buf) &&
     ("NM_A_SZ_RESULT_CODE" >< buf) &&
     ("53505" >< buf) &&
     ("NM_A_SZ_TRANSACTION_ID" >< buf)
   )
  security_note (port);
