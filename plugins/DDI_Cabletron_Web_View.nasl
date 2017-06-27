#
# This script was written by Forrest Rae
#

# Changes by Tenable:
# - Added OSVDB ref (1/22/09)
# - Changed family (8/31/09)

include("compat.inc");

if(description)
{
	script_id(10962);
	script_version ("$Revision: 1.17 $");

        # script_cve_id("CVE-MAP-NOMATCH");
 	script_osvdb_id(786);
        # NOTE: reviewed, and no CVE id currently assigned (jfs, december 2003)
 
 	script_name(english:"Cabletron WebView Administrative Access");
 	script_summary(english:"Cabletron WebView Administrative Access");
 
	script_set_attribute(attribute:"synopsis", value:
"The remote web server allows uncredentialed administrative access.");
	script_set_attribute(attribute:"description", value:
"This host is a Cabletron switch and is running Cabletron WebView. 
This web software provides a graphical, real-time representation of
the front panel on the switch.  This graphic, along with additionally
defined areas of the browser interface, allow you to interactively
configure the switch, monitor its status, and view statistical
information.  An attacker can use this to gain information about this
host.");
	script_set_attribute(attribute:"solution", value:
"Depending on the location of the switch, it might be advisable to
restrict access to the web server by IP address or disable the web
server completely.");
    script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
	script_set_attribute(attribute:"plugin_publication_date", value:
"2002/05/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/01/01");
 script_cvs_date("$Date: 2015/10/21 20:34:20 $");
	script_set_attribute(attribute:"plugin_type", value:"remote");
	script_end_attributes();

	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002-2011 Digital Defense Incorporated");
	script_family(english:"Web Servers");
	script_dependencie("http_version.nasl");
        script_require_ports("Services/www");
	exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if(get_port_state(port))
{
	soc = http_open_socket(port);
	if(soc)
	{
		req = http_get(item:string("/chassis/config/GeneralChassisConfig.html"), port:port);
		send(socket:soc, data:req);
		
		r = http_recv(socket:soc);
		     
		if(!isnull(r) && "Chassis Configuration" >< r)
		{
			security_hole(port:port); 
			set_kb_item(name:"Services/www/" + port + "/embedded", value:TRUE);
			exit(0);
		}

		http_close_socket(soc);
	}
}



