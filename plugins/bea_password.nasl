#
# Written by Astharot <astharot@zone-h.org>
#
# UNTESTED


include("compat.inc");

if(description)
{
 script_id(12043);
 script_version ("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/03/05 23:17:30 $");

 script_cve_id("CVE-2004-1757");
 script_bugtraq_id(9501);
 script_osvdb_id(3727);
 script_xref(name:"CERT", value:"350350");
 
 script_name(english:"BEA WebLogic config.xml Operator/Admin Password Disclosure");
 script_summary(english:"Checks the version of WebLogic");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a password disclosure 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server is running WebLogic.  BEA WebLogic Server and
WebLogic Express are reportedly may allow disclosure of Operator or
Admin passwords.  An attacker who has interactive access to the
affected managed server may potentially exploit this issue in a timed
attack to harvest credentials when the managed server fails during the
boot process." );
 script_set_attribute(attribute:"solution", value:
"Apply vendor-supplied patches." );
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/02/05");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/27");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2004-2014 Astharot");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/weblogic");
 exit(0);
}

#

include("http_func.inc");

port = get_http_port(default:80);

if (! get_port_state(port)) exit(0);

sig = get_kb_item("www/hmap/" + port  + "/description");
if ( sig && "WebLogic" >!< sig ) exit(0);

banner = get_http_banner(port:port);

if ("Temporary Patch for CR127930" >< banner) exit(0);


if (egrep(pattern:"^Server:.*WebLogic ([6-8]\..*)", string:banner))
{
  security_warning(port);
}

