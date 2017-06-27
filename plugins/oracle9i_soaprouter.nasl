#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

# Changes by Tenable:
# - Revised plugin title, added OSVDB ref, enhanced description (6/10/09)

include("compat.inc");

if (description)
{
 script_id(11227);
 script_version("$Revision: 1.17 $");
 script_cvs_date("$Date: 2014/08/28 03:40:59 $");

 script_cve_id("CVE-2001-1371");
 script_bugtraq_id(4289);
 script_osvdb_id(5407);
 script_xref(name:"CERT-CC", value:"CA-2002-08");
 script_xref(name:"CERT", value:"476619");

 script_name(english:"Oracle 9iAS Default SOAP Configuration Unauthorized Application Deployment");
 script_summary(english:"Tests for Oracle9iAS default SOAP installation");
 
 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be run on the remote host.");
 script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS v.1.0.2.2, it is possible to
deploy or undeploy SOAP services without the need of any kind of
credentials.  This is due to SOAP being enabled by default after
installation in order to provide a convenient way to use SOAP samples. 
However, this feature poses a threat to HTTP servers with public access
since remote attackers can create soap services and then invoke them
remotely.  Since SOAP services can contain arbitrary Java code in Oracle
9iAS this means that an attacker can execute arbitrary code in the
remote server.");
 script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technology/deploy/security/pdf/ias_soap_alert.pdf");
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/papers/hpoas.pdf");
 script_set_attribute(attribute:"solution", value:
"Disable SOAP or the deploy/undeploy feature by editing
$ORACLE_HOME/Apache/Jserver/etc/jserv.conf and removing/commenting
the following four lines :

ApJServGroup group2 1 1 $ORACLE_HOME/Apache/Jserv/etc/jservSoap.properties
ApJServMount /soap/servlet ajpv12://localhost:8200/soap
ApJServMount /dms2 ajpv12://localhost:8200/soap
ApJServGroupMount /soap/servlet balance://group2/soap

Note that the port number might be different from  8200.
Also, you will need to change in the file 
$ORACLE_HOME/soap/werbapps/soap/WEB-INF/config/soapConfig.xml:
<osc:option name='autoDeploy' value='true' />
to
<osc:option name='autoDeploy' value='false' />");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(264);

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/11/30");
 script_set_attribute(attribute:"plugin_publication_date", value:"2003/02/11");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:application_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2014 Javier Fernandez-Sanguino");
 script_family(english:"Databases");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("http_func.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for /soap/servlet/soaprouter

 req = http_get(item:"/soap/servlet/soaprouter", port:port);
 soc = http_open_socket(port);
 if(soc)
 {
 send(socket:soc, data:req);
 r = http_recv(socket:soc);
 http_close_socket(soc);
 if("SOAP Server" >< r)	
 	security_hole(port);

 }
}
