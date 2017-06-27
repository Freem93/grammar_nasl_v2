#
# This script was written by Paul Ewing <ewing@ima.umn.edu>
#
# See the Nessus Scripts License for details
#


include("compat.inc");

if(description) {
    script_id(10462);
    script_version ("$Revision: 1.20 $");
    script_cvs_date("$Date: 2011/05/24 20:37:07 $");
 
    script_name(english:"AMANDA Client Version");
    script_summary(english:"Detect AMANDA client version");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a backup client." );
 script_set_attribute(attribute:"description", value:
"The remote host is running an AMANDA backup system client.  AMANDA is
a backup system that allows a single backup server to backup multiple
hosts." );
 script_set_attribute(attribute:"see_also", value:"http://www.amanda.org/" );
 script_set_attribute(attribute:"risk_factor", value:"None" );
 script_set_attribute(attribute:"solution", value:"n/a" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/07/14");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
    script_category(ACT_GATHER_INFO);
 
    script_copyright(english:"This script is Copyright (C) 2000-2011 Paul J. Ewing Jr.");
    script_family(english:"Service detection");
    exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");

function get_version(soc, port, timeout)
{
  local_var result, temp, version, data;

    if ( ! isnull(timeout) )
     result = recv(socket:soc, length:2048, timeout:timeout);
   else
     result = recv(socket:soc, length:2048);

    if (result) {
        if (egrep(pattern:"^[^ ]+ [0-9]+\.[0-9]+", string:result)) {
	    temp = strstr(result, " ");
            temp = temp - " ";
            temp = strstr(temp, " ");
            version = result - temp;
            data = string("\n", "AMANDA version : ", version);
            security_note(port:port, extra:data, protocol:"udp");
            register_service(port:port, ipproto: "udp", proto:"amanda");
            set_kb_item(name:"Amanda/running", value:TRUE);
	}
    }
}

req = 'Amanda 2.3 REQ HANDLE 000-65637373 SEQ 954568800\nSERVICE ' + rand_str(length:8) + '\n';
if (get_udp_port_state(10080))
{
 soc1 = open_sock_udp(10080);
 if ( soc1 ) send(socket:soc1, data:req);
}
if (get_udp_port_state(10081))
{
 soc2 = open_sock_udp(10081);
 if ( soc2 )send(socket:soc2, data:req);
}
if ( soc1 ) get_version(soc:soc1, port:10080, timeout:NULL);
if ( soc2 ) get_version(soc:soc2, port:10081, timeout:1);
