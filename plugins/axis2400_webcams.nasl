#
# (C) Tenable Network Security, Inc.
#
# Ref:
# From: Martin Eiszner <martin@websec.org>
# To: bugtraq@securityfocus.com
# Subject: axis2400 webcams
# Message-Id: <20030228104612.7f035235.martin@websec.org>
#
#
# Thanks to Martin for having sent me a sample output of /support/messages :
#
# Jan 20 15:19:04 AxisProduct camd[22]: CGI syntax error 13163 str=HTTP/1.0 400
# 


include("compat.inc");

if(description)
{
 script_id(11298);
 script_cve_id("CVE-2003-1386");
 script_bugtraq_id(6980, 6987);
 script_osvdb_id(4805, 4806, 4807, 4808);
 script_xref(name:"Secunia", value:"8217");
 
 script_version ("$Revision: 1.20 $");
 script_name(english:"Axis 2400 Network Camera Multiple Vulnerabilities");
 script_summary(english:"Reads the remote /var/log/messages");

 script_set_attribute(attribute:"synopsis", value:
"The remote video server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote Axis Network Camera is affected by multiple 
vulnerabilities :

  - It is possible for an attacker to view the remote
    '/var/log/messages' file providing an attacker with
    access to sensitive information.

  - There is a flaw in the 'buffername' and 'format'
    parameters when calling the
    '/axis-cgi/buffer/command.cgi' script which could allow
    an attacker to overwrite system files.

  - An unspecified vulnerability in the authentication code
    module results in a stack overflow." );
 script_set_attribute(attribute:"see_also", value:"http://archive.cert.uni-stuttgart.de/bugtraq/2002/12/msg00219.html" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Feb/378" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Mar/361" );
 script_set_attribute(attribute:"see_also", value:"http://archive.cert.uni-stuttgart.de/bugtraq/2003/03/msg00347.html" );
 script_set_attribute(attribute:"solution", value:
"There is no known solution at this time." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/12/20");
 script_cvs_date("$Date: 2016/11/11 20:08:42 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "os_fingerprint.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

os = get_kb_item("Host/OS");
if ( os && "Axis" >!< os ) exit(0);

# Axis is not declared as "embedded" yet, but it should
port = get_http_port(default:80, embedded: 1);
r = http_send_recv3(method:"GET", item:"/support/messages", port:port);
if (isnull(r)) exit(0);
res = strcat(r[0], r[1], '\r\n', r[2]);
if(egrep(pattern:"(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec) [0-9]*.*AxisProduct .*", string:res))
	security_warning(port);
