#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15934);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2004-2496");
 script_bugtraq_id(11877);
 script_osvdb_id(12350);
 
 script_name(english:"OpenText FirstClass HTTP Daemon /Search Large Request Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running OpenText FirstClass, a web-based unified
messaging system. 

The remote version of this software is vulnerable to an unspecified
denial of service attack that could allow an attacker to disable this
service remotely." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Dec/338" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to a version newer than FirstClass OpenText 8.0.0." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");


 script_set_attribute(attribute:"plugin_publication_date", value: "2004/12/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/12/14");
 script_cvs_date("$Date: 2016/10/10 15:57:05 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_summary(english:"Checks for FirstClass");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(banner)
{ 
  if(egrep(pattern:"^Server: FirstClass/([0-7]\.|8\.0[^0-9])", string:banner))
   	security_hole(port);
}
