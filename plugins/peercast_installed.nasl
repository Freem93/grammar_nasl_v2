#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(18418);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/01/06 23:07:25 $");

  script_name(english:"PeerCast Detection");
  script_summary(english:"Detects PeerCast");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host contains a peer-to-peer filesharing application." );
 script_set_attribute(attribute:"description", value:
"The remote host is running PeerCast, a peer-to-peer software package
that lets users broadcast streaming media." );
 script_set_attribute(attribute:"solution", value:
"Make sure use of this program is in accordance with your corporate
security policy." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/06");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Peer-To-Peer File Sharing");
  script_copyright(english:"This script is Copyright (C) 2005-2014 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 7144, 7145);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:7144);


# Identify whether PeerCast is installed.
#
# nb: at least as of 0.1212, PeerCast doesn't provide a server response
#     header if the initial page is requested so we can't use
#     get_http_banner() to identify it.
r = http_send_recv3(port:port, item:"/html/en/index.htm", method:"GET");
if (isnull(r)) exit(0, "The web server did not answer");

h = parse_http_headers(status_line: r[0], headers: r[1]);
if ("PeerCast/" >< r[1])
{
  # Extract the Server response header.
  server = "";
  foreach line (split(r[1], keep:FALSE))
  {
    line = chomp(line);
    if (strlen(line) == 0) break;
    else if (line =~ "^Server:") server = line;
  }

  # If the server response header is indeed from PeerCast...
  if (server && "Server: PeerCast/")
  {
    set_kb_item(name:"PeerCast/installed", value:TRUE);

    ver = server - "Server: PeerCast/";
    if (!ver) ver = "unknown";
    set_kb_item(name:"PeerCast/"+port+"/version", value:ver);

   report = string(
      "The remote PeerCast software uses the following Server response\n",
      "header :\n",
      "\n",
      "  ", server, "\n"
    );
    security_note(port:port, extra:report);
  }
}
