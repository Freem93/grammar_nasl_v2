#
# This script was written by Javier Fernandez-Sanguino <jfs@computer.org>
# 
# This software is distributed under the GPL license, please
# read the license at http://www.gnu.org/licenses/licenses.html#TOCGPL
#

# Changes by Tenable:
# - Revised plugin title, touched up description (6/10/09)

include("compat.inc");

if (description)
{
 script_id(11224);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2014/07/11 19:10:05 $");

 script_cve_id("CVE-2002-0568");
 script_bugtraq_id(4290);
 script_osvdb_id(3411);
 script_xref(name:"CERT-CC", value:"CA-2002-08");
 script_xref(name:"CERT", value:"476619");

 script_name(english:"Oracle 9iAS XSQLServlet soapConfig.xml Authentication Credentials Disclosure");
 script_summary(english:"Tries to retrieve Oracle9iAS SOAP configuration file");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure
vulnerability.");
 script_set_attribute(attribute:"description", value:
"In a default installation of Oracle 9iAS v.1.0.2.2.1, it is possible to
access some configuration files.  These files include detailed
information on how the product was installed on the server including
where the SOAP provider and service manager are located as well as
administrative URLs to access them.  They may also contain sensitive
information (usernames and passwords for database access).");
 script_set_attribute(attribute:"see_also", value:"http://www.nextgenss.com/papers/hpoas.pdf");
 script_set_attribute(attribute:"see_also", value:"http://otn.oracle.com/deploy/security/pdf/ojvm_alert.pdf");
 script_set_attribute(attribute:"solution", value:
"Modify the file permissions so that the web server process cannot
retrieve it.  Note however that if the XSQLServlet is present it might
bypass filesystem restrictions.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2002/01/10");
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
include("http_keepalive.inc");

port = get_http_port(default:80);


if(get_port_state(port))
{ 
# Make a request for the configuration file

# Note: this plugin can be expanded, I removed the call to 
# SQLConfig since it's already done directly in #10855
 config[0]="/soapdocs/webapps/soap/WEB-INF/config/soapConfig.xml";
# config[1]="/xsql/lib/XSQLConfig.xml"; # Already done by plugin #10855

 for(i = 0; config[i] ; i = i+1 )
 {
     req = http_get(item:config[i], port:port);
     r = http_keepalive_send_recv(port:port, data:req, bodyonly:1);
     if(r == NULL) exit(0);
     if ( "SOAP configuration file" >< r )
     {
       report = string(
         "\n",
         "The following SOAP configuration file can be accessed directly :\n",
         "\n",
         "  File : ", config[i], "\n",
         "  URL  : ", build_url(port:port, qs:config[i]), "\n"
       );
       if (report_verbosity > 1)
       {
         report = string(
           report,
           "\n",
           "Here are its contents :\n",
           "\n",
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n",
           r,
           crap(data:"-", length:30), " snip ", crap(data:"-", length:30), "\n"
         );
       }
       security_warning(port:port, extra:report);
     }
 } # of the for loop
}
