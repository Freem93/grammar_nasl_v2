#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10049);
 script_bugtraq_id(128);
 script_osvdb_id(42);
 script_version ("$Revision: 1.33 $");
 script_cve_id("CVE-1999-0021");

 script_name(english:"wwwcount Count.cgi Remote Overflow");
 script_summary(english:"Checks Count.cgi version");

 script_set_attribute(attribute:"synopsis", value:
"A web application on the remote web server has a buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"According to its version number, the 'Count.cgi' CGI installed on the
remote web server has a buffer overflow vulnerability.  A remote
attacker could use this to execute arbitrary code." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1997/Oct/82"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/1997/Oct/84"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to wwwcount 2.4 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/10/16");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english: "CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
foreach d (cgi_dirs())
{
  rr = http_send_recv3(method: "GET", port: port, item: strcat(d, "/Count.cgi?align=topcenter"));
  r = strstr(rr[1]+rr[2], "Count.cgi ");
  if (r && ereg(string:r, pattern:".*Count\.cgi +([01]\.[0-9]+|2\.[0-3]+)"))
  {
    security_hole(port);
    exit(0);
  }
}
