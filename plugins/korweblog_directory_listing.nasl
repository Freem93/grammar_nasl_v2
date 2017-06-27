#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15829);
 script_version("$Revision: 1.17 $");

 script_cve_id("CVE-2004-1426", "CVE-2004-1427", "CVE-2004-1543");
 script_bugtraq_id(11744, 12132);
 script_osvdb_id(12114, 12679, 12680);
 
 script_name(english:"KorWeblog < 1.6.2 Multiple Vulnerabilities");
 
 script_set_attribute(
  attribute:"synopsis",
  value:
"The remote web server hosts a PHP application that is affected by
multiple vulnerabilities."
 );
 script_set_attribute(
  attribute:"description", 
  value:
"The remote host is using KorWeblog, a web-based log application
written in PHP. 

According to its banner, the installed version of KorWeblog is earlier
than 1.6.2.  Such versions are affected by reportedly affected by
several vulnerabilities that may allow execution of arbitrary PHP code
or retrieval of files on the affected host, subject to the permissions
under which the web server operates."
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/fulldisclosure/2004/Nov/1116"
 );
 script_set_attribute(
  attribute:"see_also", 
  value:"http://seclists.org/bugtraq/2004/Dec/449"
 );
 script_set_attribute(
  attribute:"solution", 
  value:"Upgrade to KorWeblog 1.6.2 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(
  attribute:"vuln_publication_date", 
  value:"2004/11/23"
 );
 script_set_attribute(
  attribute:"plugin_publication_date", 
  value:"2004/11/24"
 );
 script_cvs_date("$Date: 2016/11/19 01:42:51 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Checks the version of the remote KorWeblog");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

function check(loc)
{
 local_var r, w;

 w = http_send_recv3(method:"GET", item:string(loc, "/index.php"), port:port);
 if (isnull(w)) exit(0);
 r = strcat(w[0], w[1], '\r\n', w[2]);
 if (ereg(pattern:"Powered by <A HREF=.*KorWeblog 1\.([0-5]\..*|6\.[0-1][^0-9].*)/A>", string:r))
   {
    security_warning(port);
    exit(0);
   }
}

foreach dir (cgi_dirs())
{
 check(loc:dir);
}

