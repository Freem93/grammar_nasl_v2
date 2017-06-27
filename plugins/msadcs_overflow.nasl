#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(11161);
 script_version ("$Revision: 1.38 $");
 script_cve_id("CVE-2002-1142");
 script_bugtraq_id(6214);
 script_osvdb_id(14502);
 script_xref(name:"MSFT", value:"MS02-065");

 script_name(english:"Microsoft Data Access Components RDS Data Stub Remote Overflow");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is affected by a remote buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote DLL /msadc/msadcs.dll is accessible by anyone. Several 
flaws have been found in it in the past. We recommend that you restrict 
access to MSADC only to trusted hosts." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms02-065" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2002/q4/60" );
 script_set_attribute(attribute:"solution", value:
"  - Launch the Internet Services Manager
  - Select your web server
  - Right-click on MSADC and select 'Properties'
  - Select the tab 'Directory Security'
  - Click on the 'IP address and domain name restrictions'
    option
  - Make sure that by default, all computers are DENIED access
    to this resource
  - List the computers that should be allowed to use it" );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS02-065 Microsoft IIS MDAC msadcs.dll RDS DataStub Content-Type Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_publication_date", value: "2002/11/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/11/20");
 script_cvs_date("$Date: 2016/10/27 15:03:55 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines the presence of msadcs.dll");
 script_category(ACT_MIXED_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if(safe_checks() &&  report_paranoia < 2)
  exit(0, "This script only runs in 'Paranoid' mode when safe_checks is set.");


port = get_http_port(default:80);

  w = http_send_recv3(method:"POST", port: port, item:"/msadc/msadcs.dll",
    content_type: "text/plain", exit_on_fail: 1, data: "X");
  z = strcat(w[1], w[2]);
  if(!z) exit(1, "Empty HTTP response on port "+port+".");
  if ("Content-Type: application/x-varg" >!< z) exit(0, "Content-Type received from port "+port+" is not application/x-varg.");

if (safe_checks())
{
    e = "
*** Nessus did not test for any security vulnerability but solely relied
*** on the presence of this resource to issue this warning, so this 
*** might be a false positive."; 
    security_hole(port:port, extra: e);
    exit(0);
}
else
{
 #
 # Okay, it turns out that this method crashes HTTP/1.0
 # support in IIS (not HTTP/1.1)
 # 
 w = http_send_recv3(method:"GET", port: port, item: "/nessus.asp", 
   version: 10, exit_on_fail: 1);
 
 q = raw_string(0x22);
 w = http_send_recv3(method:"POST", port: port,
   item: "/msadc/msadcs.dll/AdvancedDataFactory.Query",
   exit_on_fail: 0,
   content_type: string("application/", crap(32768), ";bob=", q, "bob", q),
   data: "");

 sleep(1);

 w = http_send_recv3(method:"GET", port: port, item: "/nessus.asp", 
   version: 10, exit_on_fail: 0);
 if (isnull(w)) security_hole(port);
 else
   exit(0, "MSDACS on port "+port+" is not affected.");
}
