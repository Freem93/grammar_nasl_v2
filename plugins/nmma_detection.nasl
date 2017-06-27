#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(21242);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2011/11/15 01:21:02 $");

  script_name(english:"Novell Messenger Messaging Agent Detection");
  script_summary(english:"Checks for Novell Messenger Messaging Agent");

  script_set_attribute(attribute:"synopsis", value:
"The remote host is running an instant messaging server.");
  script_set_attribute(attribute:"description", value:
"The remote host is running Novell Messenger Messaging Agent, an
enterprise instant messaging server for Windows, Linux, and NetWare.");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/04/19");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Service detection");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencie("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8300);

  exit(0);
}

include("global_settings.inc");
include ("misc_func.inc");
include ("http.inc");


port = get_http_port (default:8300);

data = '&tag=NM_A_SZ_TRANSACTION_ID_A&cmd=0&val=1&type=10\r\n';

http_disable_keep_alive();
res = http_send_recv3(port:port, method:'POST', item:'/topic', data:data, exit_on_fail:TRUE);

# server should return HTTP status code 200 for a topic command
if (res[0] =~ "^HTTP/1\.[0-9]+[ \t]+200")
{
  if (!isnull(res[2]))
  { 
    if (
      'NM_A_SZ_RESULT_CODE' >< res[2] &&
      "53505" >< res[2] &&                       # the code means bad parameter
      "NM_A_SZ_TRANSACTION_ID" >< res[2]
    )
    {
       set_kb_item (name:string ("Novell/NMMA/", port), value:TRUE);
       register_service(port:port, proto:'novell-nmma');
       security_note(port);
    }
    else exit(0, 'The service listening on port '+port+' returned unexpected HTTP data.'); 
  }
  else exit(0, 'The service listening on port '+port+' did not return HTTP data.'); 
}
else exit(0, 'The service listening on port '+port+' returned an unexpected HTTP status code.'); 
