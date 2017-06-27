#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(15555);
 script_version("$Revision: 1.22 $");
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_cve_id("CVE-2004-0492");
 script_bugtraq_id(10508);
 script_osvdb_id(6839);
 script_xref(name:"RHSA", value:"2004:245");
 script_xref(name:"Secunia", value:"11841");
 script_xref(name:"Secunia", value:"11854");
 script_xref(name:"Secunia", value:"11859");
 script_xref(name:"Secunia", value:"11866");
 script_xref(name:"Secunia", value:"11917");
 script_xref(name:"Secunia", value:"11946");
 script_xref(name:"Secunia", value:"11957");
 script_xref(name:"Secunia", value:"11968");
 script_xref(name:"Secunia", value:"12971");
 script_xref(name:"Secunia", value:"13115");

 script_name(english:"Apache mod_proxy Content-Length Overflow");
 script_summary(english:"Checks for version of Apache");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a heap-based buffer overflow
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote web server appears to be running a version of Apache that
is older than version 1.3.32.

This version is reportedly vulnerable to a heap-based buffer overflow
in proxy_util.c for mod_proxy. This issue may lead remote attackers to
cause a denial of service and possibly execute arbitrary code on the
server." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Jun/293" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Jun/297" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Apache 1.3.32 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/06/10");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:apache:http_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "os_fingerprint.nasl");
 if ( defined_func("bn_random") )
  script_dependencie("mandrake_MDKSA-2004-065.nasl", "redhat-RHSA-2004-244.nasl", "macosx_SecUpd20041202.nasl");

 script_require_keys("www/apache");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("http_func.inc");
include("backport.inc");

if ( get_kb_item("CVE-2004-0492") ) exit(0);

port = get_http_port(default:80);
if(!port)exit(0);
if(!get_port_state(port))exit(0);

banner = get_backport_banner(banner:get_http_banner(port: port));
if(!banner)exit(0);

serv = strstr(banner, "Server");
if(ereg(pattern:"^Server:.*Apache(-AdvancedExtranetServer)?/(1\.(3\.(2[6-9]|3[01])))([^0-9]|$)", string:serv))
 {
   security_hole(port);
   exit(0);
 }
