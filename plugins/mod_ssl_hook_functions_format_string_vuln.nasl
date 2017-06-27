#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(13651);
 script_version("$Revision: 1.23 $");
 script_cvs_date("$Date: 2013/05/28 17:31:51 $");

 script_cve_id("CVE-2004-0700");
 script_bugtraq_id(10736);
 script_osvdb_id(7929);

 script_name(english:"Apache mod_ssl ssl_engine_log.c mod_proxy Hook Function Remote Format String");
 script_summary(english:"Checks for version of mod_ssl");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is using a module that is affected by a remote
code execution vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is using a version vulnerable of mod_ssl which is
older than 2.8.19. There is a format string condition in the log
functions of the remote module which may allow an attacker to execute
arbitrary code on the remote host.

*** Some vendors patched older versions of mod_ssl, so this
*** might be a false positive. Check with your vendor to determine
*** if you have a version of mod_ssl that is patched for this
*** vulnerability");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=apache-modssl&m=109001100906749&w=2");
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=109005001205991&w=2");
 script_set_attribute(attribute:"solution", value:
"Upgrade to mod_ssl version 2.8.19 or newer");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/07/16");
 script_set_attribute(attribute:"vuln_publication_date", value:"2004/07/16");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/apache");
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include('backport.inc');

if ( get_kb_item("CVE-2004-0700") ) exit(0);

port = get_http_port(default:80);

if(get_port_state(port))
{
 banner = get_backport_banner(banner:get_http_banner(port:port));
 if(!banner || backported )exit(0);
 if ( "Darwin" >< banner )exit(0);

 serv = strstr(banner, "Server");
 if("Apache/" >!< serv ) exit(0);
 if("Apache/2" >< serv) exit(0);
 if("Apache-AdvancedExtranetServer/2" >< serv)exit(0);

 if(ereg(pattern:".*mod_ssl/(1.*|2\.([0-7]\..*|8\.([0-9]|1[0-8])[^0-9])).*", string:serv))
 {
   security_hole(port);
 }
}
