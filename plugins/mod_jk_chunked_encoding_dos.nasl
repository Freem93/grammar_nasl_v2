#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11519);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2002-2272");
 script_bugtraq_id(6320);
 script_osvdb_id(7394, 34398);
 
 script_name(english:"Apache Tomcat mod_jk Invalid Transfer-Encoding Chunked Field DoS");
 script_summary(english:"Checks for version of mod_jk");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server module has a denial of service vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"According to the banner, the remote host is using a vulnerable
version of the Apache mod_jk module.  Such versions have a bug that
could allow a remote attacker to use chunked encoding requests to
desynchronize Apache and Tomcat, and therefore prevent the remote web
server from working properly." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2002/Dec/47"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_jk 1.2.1 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(119);
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/04");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/12/04");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
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
if(!banner)exit(0);
serv = strstr(banner, "Server:");
 
if(ereg(pattern:".*mod_jk/1\.([0-1]\..*|2\.0)", string:serv))
{
  security_warning(port);
}
