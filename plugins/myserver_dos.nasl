#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11770);
 script_version ("$Revision: 1.22 $");

 script_bugtraq_id(7917, 8120);
 script_osvdb_id(2189, 2273, 2808, 53793);
 
 script_name(english:"MyServer <= 0.4.2 Multiple Remote DoS");
 script_summary(english:"Checks for the presence of MyServer");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a denial of service 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running MyServer 0.4.2 or older. 

There are flaws in this software that could allow an attacker
to disable this service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2003/Jul/99" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MyServer 4.3 as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/23");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/06/22");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner) exit(0);
if(egrep(pattern:"^Server:MyServer 0\.([0-3]\.|4\.[0-2])[^0-9]", string:banner))
	{
	  security_warning(port);
	}


