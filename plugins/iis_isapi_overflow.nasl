#
# (C) Tenable Network Security, Inc.
#

# This script was written by Renaud Deraison <deraison@cvs.nessus.org>
# It was modified by H D Moore to not crash the server during the test
#
# Supercedes MS01-033


include("compat.inc");

if(description)
{
 script_id(10685);
 script_version ("$Revision: 1.48 $");
 script_cve_id( "CVE-2001-0544", "CVE-2001-0545", "CVE-2001-0506", "CVE-2001-0507", "CVE-2001-0508", "CVE-2001-0500");
 script_bugtraq_id(2690, 2880, 3190, 3193, 3194, 3195);
 script_osvdb_id(1930, 1931, 5584, 5606, 5633, 568, 5736);
 script_xref(name:"MSFT", value:"MS01-033");
 script_xref(name:"MSFT", value:"MS01-044");
 
 script_name(english:"Microsoft IIS ISAPI Filter Multiple Vulnerabilities (MS01-044)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"There's a buffer overflow in the remote web server through
the ISAPI filter.
 
It is possible to overflow the remote web server and execute 
commands as user SYSTEM.

Additionally, other vulnerabilities exist in the remote web
server since it has not been patched." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-033" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-044" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches from the bulletins above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"exploit_framework_core", value:"true");
 script_set_attribute(attribute:"exploited_by_malware", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'MS01-033 Microsoft IIS 5.0 IDQ Path Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2001/06/19");
 script_set_attribute(attribute:"patch_publication_date", value: "2001/06/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/05/06");
 script_cvs_date("$Date: 2016/11/23 20:31:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
script_end_attributes();


 script_summary(english:"Tests for a remote buffer overflow in IIS");
 script_category(ACT_ATTACK);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2001-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

# The attack starts here
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);
b = get_http_banner(port: port);
if ("IIS" >!< h ) exit(0);
   
     
w = http_send_recv3(method: "GET", port: port,
  item: "/x.ida?"+crap(length:220, data:"x")+"=x");
if (isnull(w)) exit(1, "the web server did not answer");
r = strcat(w[0], w[1], '\r\n', w[2]);

    # 0xc0000005 == "Access Violation"
    if ("0xc0000005" >< r)
    {
        security_hole(port);
    }

