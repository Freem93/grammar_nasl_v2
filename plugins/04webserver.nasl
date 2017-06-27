#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(15713);
 script_cve_id("CVE-2004-1512", "CVE-2004-1513", "CVE-2004-1514");
 script_bugtraq_id(11652);
 script_osvdb_id(11606, 11607, 11608);
 script_version("$Revision: 1.18 $");
 
 script_name(english:"04WebServer Multiple Vulnerabilities (XSS, DoS, more)");
 script_summary(english:"Checks for version of 04WebServer");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is susceptible to several forms of attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of 04WebServer which is older
than version 1.5. Such versions are affected by multiple
vulnerabilities :
  
  - A cross-site scripting vulnerability in the
    Response_default.html script which could allow an attacker
    to execute arbitrary code in the user's browser.

  - A log file content injection vulnerability which could
    allow an attacker to insert false entries into the log
    file.

  - A DoS vulnerability caused by an attacker specifying a
    DOS device name in the request URL." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/142");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2004/Nov/197");
 script_set_attribute(attribute:"see_also", value:"http://attrition.org/pipermail/vim/2006-August/000978.html");
 script_set_attribute(attribute:"see_also", value:"http://www.security.org.sg/vuln/04webserver142.html");

 script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.5 of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/11/13");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/11/11");
 script_cvs_date("$Date: 2016/09/22 15:18:21 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencies("http_version.nasl");
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

banner = get_http_banner(port: port);
if(!banner)exit(0);
 
serv = strstr(banner, "Server");
if(ereg(pattern:"^Server: 04WebServer/(0\.|1\.([0-9][^0-9]|[0-3][0-9]|4[0-2]))", string:serv))
 {
   security_warning(port);
   set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }
