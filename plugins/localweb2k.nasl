# This script was created by Jason Lidow <jason@brandx.net>
# The vulnerability was originally discovered by ts@securityoffice.net 

# Changes by Tenable:
# - Revised plugin title, output formatting, family change (9/5/09)


include("compat.inc");

if(description)
{
	script_id(11005);
	script_version("$Revision: 1.24 $");
	script_cve_id("CVE-2001-0189", "CVE-2002-0897");
	script_bugtraq_id(2268, 4820, 7947);
	script_osvdb_id(825, 5055);

	script_name(english:"LocalWeb2000 2.1.0 Multiple Remote Vulnerabilities");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is vulnerable to several information disclosure flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running LocalWeb2000. 

Version 2.1.0 of LocalWeb2000 allows an attacker to view protected 
files on the host's computer. 

It may also disclose the NetBIOS name of the remote host when
it receives malformed directory requests." );
 script_set_attribute(attribute:"solution", value:
"Contact http://www.intranet-server.co.uk for an update." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2002/06/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/01/19");
 script_cvs_date("$Date: 2016/11/23 20:31:33 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


	script_summary(english:"Checks for LocalWeb2000");
	script_category(ACT_GATHER_INFO);
	script_copyright(english:"This script is Copyright (C) 2002-2016 Jason Lidow <jason@brandx.net>");
	script_family(english:"Web Servers");
	script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl");
	script_require_ports("Services/www", 80);
	exit(0);
}

include("http_func.inc");

port = get_http_port(default:80);


if(!get_port_state(port))exit(0);


banner = get_http_banner(port:port);
  
  

if(banner)
{
	if(egrep(pattern:"^Server: .*LocalWEB2000.*" , string:banner, icase:TRUE))
	{
	security_hole(port);
	}
}
