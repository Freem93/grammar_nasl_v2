#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(11538);
 script_version ("$Revision: 1.19 $");

 script_bugtraq_id(7347);
 script_osvdb_id(6560);
 script_xref(name:"Secunia", value:"8606");

 script_name(english:"eZ Publish settings/site.ini Configuration Disclosure");
 script_summary(english:"Determine if eZ Publish config file can be retrieved");

 script_set_attribute( attribute:"synopsis", value:
"A web application on the remote host has an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description",  value:
"eZ Publish, a content management system, is installed on the remote
host.

A remote attacker can retrieve the file 'settings/site.ini', which
contains information such as database name, username, and password.
This information could be used to mount further attacks.

This version of eZ Publish also has multiple cross-site scripting
vulnerabilities, though Nessus has not checked for those issues." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/Apr/208"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Prevent .ini files from being downloaded from the web server."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/04/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/04/15");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
dir = make_list(cgi_dirs());

foreach d (dir)
{
 url = string(d, "/settings/site.ini");
 buf = http_send_recv3(method:"GET", item:url, port:port);
 if( isnull(buf) ) exit(0);
 
 if (
   "ConnectRetries" >< buf[2] &&
   "UseBuiltinEncoding" >< buf[2]
 )
 {
   security_warning(port:port);
   exit(0);
 }
}

