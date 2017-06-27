#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25149);
  script_version("$Revision: 1.13 $");

  script_cve_id("CVE-2007-1868");
  script_bugtraq_id(23264);
  script_osvdb_id(34678);

  script_name(english:"IBM Tivoli Provisioning Manager OS Deployment Multiple Stack Overflows");
  script_summary(english:"Gets IBM TPM for OS Deployment Server version");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running IBM Tivoli Provisioning Manager for OS
Deployment.  The version of this software has multiple buffer overflow
vulnerabilities in the HTTP server. 

A remote attacker may exploit these flaws to crash the service or
execute code on the remote host with the privileges of the TPM server." );
 script_set_attribute(attribute:"see_also", value:"http://dvlabs.tippingpoint.com/advisory/TPTI-07-05" );
 script_set_attribute(attribute:"solution", value:
"Install TPM for OS Deployment Fix Pack 2 with Interim Fix 2." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"metasploit_name", value:'IBM TPM for OS Deployment 5.1.0.x rembo.exe Buffer Overflow');
 script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2007/05/03");
 script_set_attribute(attribute:"patch_publication_date", value: "2007/04/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "2007/04/01");
 script_cvs_date("$Date: 2012/10/03 21:39:19 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:ibm:tivoli_provisioning_manager_os_deployment");
 script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2012 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080, 443);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if ("Server: Rembo" >!< banner)
  exit (0);

w = http_send_recv3(method:"GET", item:"/builtin/index.html", port:port);
if (isnull(w)) exit(1, "the web server did not answer");
res = w[2];

pat = '<p style="font:  12px Verdana, Geneva, Arial, Helvetica, sans-serif;"><b>TPMfOSd ([0-9]+\\.[0-9]+\\.[0-9]+\\.[0-9]+) \\(build ([0-9]+\\.[0-9]+)\\)</b>.*';

version = egrep(pattern:pat, string:res);
if (!version)
  exit (0);

vers = ereg_replace(pattern:pat, string:version, replace:"\1");
vers = split (vers, sep:".", keep:FALSE);

if ( (int(vers[0]) < 5) ||
     (int(vers[0]) == 5 && int(vers[1]) < 1) ||
     (int(vers[0]) == 5 && int(vers[1]) == 1 && int(vers[2]) == 0 && int(vers[3]) < 2) )
  security_hole(port);

if ( int(vers[0]) == 5 && int(vers[1]) == 1 && int(vers[2]) == 0 && int(vers[3]) == 2 )
{
 build = ereg_replace(pattern:pat, string:version, replace:"\2");
 build = split (build, sep:".", keep:FALSE);

 if ( (int(build[0]) < 12) ||
      (int(build[0]) == 12 && int(build[1]) < 4) )
   security_hole(port);
}
