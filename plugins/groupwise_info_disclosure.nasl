#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(16175);
  script_version("$Revision: 1.15 $");
  script_bugtraq_id(12194);
  script_osvdb_id(13021);
  
  script_name(english:"Novell GroupWise WebAccess WebAccessUninstall.ini Information Disclosure");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Novell GroupWise WebAccess, a commercial
groupware package.

The remote version of this software has an information disclosure
vulnerability.  An attacker may request the file
'/com/novell/webaccess/WebAccessUninstall.ini' and will obtain some
information about the remote host paths and setup." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2005/Jan/263" );
 script_set_attribute(attribute:"solution", value:
"Delete /com/novell/webaccess/WebAccessUninstall.ini" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/15");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/07");
 script_cvs_date("$Date: 2016/10/10 15:57:06 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

  script_summary(english:"Checks GroupWare WebAccessUninstall.ini");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencie("http_version.nasl");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);


r = http_send_recv3(method:"GET", item:"/com/novell/webaccess/WebAccessUninstall.ini", port:port);
if( isnull(r) )exit(0);

if("NovellRoot=" >< r[2] )
{
  security_warning(port);
#  set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
  exit(0);
}
