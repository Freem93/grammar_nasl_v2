#
# (C) Tenable Network Security, Inc.
#

# The overflow occurs *after* the server replied to us, so it can only
# be detected using the banner of the server
#

include("compat.inc");

if(description)
{
 script_id(11809);
 script_version("$Revision: 1.20 $");
 script_cve_id("CVE-2003-0651");
 script_bugtraq_id(8287);
  script_osvdb_id(10976);
  script_xref(name:"EDB-ID", value:"67");
 script_xref(name:"Secunia", value:"9375");
 
 script_name(english:"mod_mylo for Apache mylo_log Logging Function HTTP GET Overflow");
 script_summary(english:"Checks for version of mod_mylo");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server module has a buffer overflow vulnerability."
 );
 script_set_attribute( attribute:"description",  value:
"According to the banner, the remote host is using a vulnerable
version of mylo_log, a MySQL logging module for Apache.  Such
versions have a buffer overflow vulnerability which could result
in arbitrary code execution." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Jul/80"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_mylo 0.2.2 or later."
 );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/07/28");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/07/28");
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
if(ereg(pattern:".*Mylo/(0\.[0-2]).*", string:serv))
{
  security_hole(port);
}
