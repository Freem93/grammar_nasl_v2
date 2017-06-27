#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10001);
 script_version("$Revision: 1.46 $");
 script_cvs_date("$Date: 2016/10/07 13:30:47 $");

 script_cve_id("CVE-1999-0455", "CVE-1999-0477");
 script_bugtraq_id(115);
 script_osvdb_id(1, 50620);

 script_name(english:"ColdFusion Multiple Vulnerabilities (File Upload/Manipulation)");
 script_summary(english:"Checks for a ColdFusion vulnerability");

 script_set_attribute(attribute:"synopsis", value:
"The remote application server is affected by multiple vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The 'exprcalc.cfm' page in the version of Cold Fusion Application
Server running on the remote host allows an unauthenticated, remote
attacker to read arbitrary files and possibly delete or upload
arbitrary files as well.");
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/1999/Apr/198");
 script_set_attribute(attribute:"solution", value:
"Contact the vendor for a patch.

In addition to this patch, it is recommended that the documentation
and example code not be stored on production servers.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"1998/12/25");
 script_set_attribute(attribute:"patch_publication_date", value:"1999/02/04");
 script_set_attribute(attribute:"plugin_publication_date", value:"1999/07/09");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:allaire:coldfusion_server");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_keys("Settings/ParanoidReport");
 script_require_ports("Services/www", 80);

 exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

#
# The script code starts here
#

port = get_http_port(default:80);

cgi  = "/cfdocs/expeval/ExprCalc.cfm?OpenFilePath=c:\winnt\win.ini";
cgi2 = "/cfdocs/expeval/ExprCalc.cfm?OpenFilePath=c:\windows\win.ini";
y = is_cgi_installed3(item:cgi, port:port);
if(!y){
	y = is_cgi_installed3(item:cgi2, port:port);
	cgi = cgi2;
	}


if(y){
        res = http_send_recv3(method:"GET", item:cgi, port:port);
  	if ( isnull(res) ) exit(0);
	if( "[fonts]" >< res )
		security_hole(port);
	}
