#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16183);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2005-0296");
  script_bugtraq_id(12285);
  script_osvdb_id(13141, 13142);
 
  script_name(english:"Novell GroupWise WebAccess Error Handler Authentication Bypass");
  script_summary(english:"Checks GroupWise Auth Bypass");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running a web application that is affected by a
remote authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, a commercial
groupware package.

The remote version of this software is prone to an authentication
bypass attack. 

An attacker requesting :

	/servlet/webacc?error=webacc

may bypass the authentication mechanism and gain access to the groupware
console." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/387566/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/17");
 script_cvs_date("$Date: 2011/03/14 21:48:04 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

r = http_send_recv3(method:"GET", item:"/servlet/webacc?error=webacc", port:port);
if( r == NULL )exit(0);

if ( "<TITLE>Novell WebAccess ()</TITLE>" >< r[2] &&
     "/servlet/webacc?User.context=" >< r[2] )
	security_warning(port);
