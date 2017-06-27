#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10159);
 script_version ("$Revision: 1.23 $");
 script_cvs_date("$Date: 2011/03/11 21:18:09 $");
 name["english"] = "NNTP Server Detection";
 script_name(english:name["english"]);

 script_set_attribute(attribute:"synopsis", value:
"An NNTP server is listening on the remote port" );
 script_set_attribute(attribute:"description", value:
"The remote host is running a news server (NNTP).  Make sure that
hosting such a server is authorized by your company policy." );
 script_set_attribute(attribute:"solution", value:
"Disable this service if you do not use it." );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/10/12");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 summary["english"] = "NNTP Server Detection";;
 script_summary(english:summary["english"]);
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Service detection");

 script_dependencie("find_service_3digits.nasl", "doublecheck_std_services.nasl");
 script_require_ports("Services/nntp", 119);
 
 exit(0);
}

#
# The script code starts here
#
include("ftp_func.inc");
include("misc_func.inc");

port = get_kb_item("Services/nntp");
if ( ! port ) port = 119;
if ( ! get_port_state(port) ) exit(0);

soc = open_sock_tcp(port);
if ( ! soc ) exit(0);

r = line = recv_line(socket:soc, length:4096);
while ( r[3] == "-" )
{
 r = recv_line(socket:soc, length:4096);
 line += r;
}

if (egrep(string: line, pattern: "[ -]Leafnode NNTP Daemon"))
  set_kb_item(name: "nntp/leafnode", value: TRUE);

if ( line =~ "^200" )
	{
	send(socket:soc, data:'authinfo user ' + rand_str(length:8) + '\r\n');
	r = recv_line(socket:soc, length:255);
	if ( r =~ "^381" ) {
		report = '\nRemote server banner :\n\n  ' + line;
		security_note(port:port, extra:report);
		}
	}
close(soc);
