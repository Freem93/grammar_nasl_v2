#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(13845);
 script_cve_id("CVE-2004-2047");
 script_bugtraq_id(10792);
 script_osvdb_id(8193);
 script_version("$Revision: 1.17 $");

 script_name(english:"EasyWeb FileManager pathtext Traversal Arbitrary File/Directory Access");
 script_summary(english:"Determines if EasyWeb FileManager is present");

 script_set_attribute(attribute:"synopsis",value:
"A web application running on the remote host has a directory traversal
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the EasyWeb FileManager module
that is vulnerable to a directory traversal attack.

An attacker may use this flaw to read arbitrary files on the remote
server by sending malformed requests like :

/index.php?module=ew_filemanager&type=admin&func=manager&pathext=../../file

Note that this might be a false positive, since an attacker would need
credentials to exploit this flaw." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/vulnwatch/2004/q3/8"
 );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2004/Jul/298"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this module."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/07/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/07/23");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if(!can_host_php(port:port))exit(0);

foreach dir ( cgi_dirs() )
{
 url = string(dir, "/index.php?module=ew_filemanager&type=admin&func=manager");
 res = http_send_recv3(method:"GET", item:url, port:port);
 if(isnull(res)) exit(0);
 
 if( egrep(pattern:"_NOAUTH", string:res[2]) )
 {
    	security_warning(port);
	exit(0);
 }
}
