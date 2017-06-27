#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10405);
 script_version ("$Revision: 1.31 $");
 script_cve_id("CVE-2000-0413");
 script_bugtraq_id(1174);
 script_osvdb_id(28260);

 script_name(english:"Microsoft IIS FrontPage Server Extensions (FPSE) shtml.exe Path Disclosure");
 script_summary(english:"Retrieve the real path using shtml.exe");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server has an information disclosure vulnerability."
 );
 script_set_attribute(attribute:"description",  value:
"The version of FrontPage Extensions running on the remote host has an
information disclosure vulnerability.  Using a non-existent file as an
argument to the 'shtml.exe' CGI reveals the local absolute path of the
web root.  A remote attacker could use this information to mount
further attacks." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2000/May/89"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to FrontPage Server Extensions SR1.2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"plugin_publication_date", value: "2000/05/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/05/06");
 script_cvs_date("$Date: 2016/11/19 01:42:50 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");

 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
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
if ( "Microsoft-IIS" >!< sig ) exit(0);

url = '/_vti_bin/shtml.exe/nessus_test.exe';
result = http_send_recv3(method:"GET", item:url, port:port);
if (isnull(result)) exit(0);

if ("no such file or folder" >< result[2])
{
  result = tolower(result[2]);
  str = strstr(result, "not open");
  if (egrep(string:str, pattern:"[a-z]:\\.*", icase:TRUE))
  {
    security_warning(port);
  }
}

