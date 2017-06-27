#

# Changes by Tenable:
# - Revised plugin title, output formatting, family change (9/3/09)

include("compat.inc");

if(description)
{
 script_id(11894);
 script_version("$Revision: 1.14 $");
 script_cve_id("CVE-2003-1510");
 script_bugtraq_id(8810);
 script_osvdb_id(6518);
 
 script_name(english:"TinyWeb cgi-bin Crafted HTTP GET Request DoS");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has a denial of service vulnerability."
 );
 script_set_attribute(
   attribute:"description",
   value:
"According to its banner, the remote version of TinyWeb has a denial
of service vulnerability.  Issuing a specially crafted GET request
similar to :

  GET /cgi-bin/.%00./dddd.html

can cause the server to consume large amounts of CPU time."
 );
 script_set_attribute(
   attribute:"solution",
   value:"Contact the vendor for a patch."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/10/16");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/10");
 script_cvs_date("$Date: 2011/03/17 16:19:56 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Checks for version of TinyWeb");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Matt North");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port)) {
        ban = get_http_banner(port: port);
        if(!ban) exit(0);
        if(egrep(pattern:"^Server:.*TinyWeb/(0\..*|1\.[0-9]([^0-9]|$))",
		 string:ban))security_hole(port);
}

