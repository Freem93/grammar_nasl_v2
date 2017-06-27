#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(17614);
 script_version("$Revision: 1.18 $");
 script_cvs_date("$Date: 2015/01/14 20:12:25 $");

 script_cve_id("CVE-2005-0873");
 script_bugtraq_id(12892);
 script_osvdb_id(15050);

 script_name(english:"Oracle Reports Server test.jsp Multiple Parameter XSS");
 script_summary(english:"Tests for a XSS in Oracle Reporting Server");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by a cross-site
scripting vulnerability.");
 script_set_attribute(attribute:"description", value:
"The remote host is running Oracle Report Server, a reporting
application.  The remote version of this software contains to a
cross-site scripting vulnerability that may allow an attacker to use the
remote host to perform a cross-site scripting attack.");
 script_set_attribute(attribute:"solution", value:"Disable access to the file 'reports/Tools/test.jsp'");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/25");
 script_set_attribute(attribute:"plugin_publication_date", value:"2005/03/24");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:10g_reports_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 script_family(english:"Databases");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/OracleApache");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
if(get_kb_item(string("www/", port, "/generic_xss"))) exit(0);

w = http_send_recv3(method:"GET", item:"/reports/examples/Tools/test.jsp?repprod<script>foo</script>", port:port);
if (isnull(w)) exit(1, "the web server did not answer");

if( ' repprod<script>foo</script> ' >< w[2] )
 {
 	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
 }

