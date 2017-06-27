#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10478);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2016/05/09 20:31:00 $");

 script_cve_id("CVE-2000-0760");
 script_bugtraq_id(1532);
 script_osvdb_id(377);

 script_name(english:"Apache Tomcat Snoop Servlet Remote Information Disclosure");
 script_summary(english:"Checks for the presence of /examples/jsp/snp/anything.snp");

 script_set_attribute(attribute:"synopsis", value:
"The remote Apache Tomcat web server has a servlet installed that is
affected by an information disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"The 'snoop' Tomcat servlet is installed. This servlet gives too much
information about the remote host, such as the PATHs in use, the host
kernel version, etc.

A remote attacker can exploit this to gain more knowledge about the
host, allowing an attacker to conduct further attacks.");
 script_set_attribute(attribute:"solution", value:"Delete the 'snoop' servlet.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/07/19");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/07/22");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:apache:tomcat");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "no404.nasl", "http_version.nasl");
 script_require_ports("Services/www", 8080);
 script_require_keys("www/tomcat");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8080);

res = http_send_recv3(method:"GET", item:"/examples/jsp/snp/anything.snp", port:port);

if(ereg(pattern:"HTTP/[0-9]\.[0-9] 200 ", string:res[2]))
{
  if("Server Info: Tomcat" >< res[2])
  {
   security_warning(port);
  }
}
