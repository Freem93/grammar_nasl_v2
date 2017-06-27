#
# Msadcs.dll locate.
#
# This plugin was written in NASL by RWT roelof@sensepost.com
#

# Changes by Tenable:
# - Revised plugin title, output formatting (9/23/09)


include("compat.inc");

if(description)
{
 script_id(10357);
 script_version ("$Revision: 1.35 $");

 script_cve_id("CVE-1999-1011");
 script_bugtraq_id(529);
 script_osvdb_id(272);

 script_name(english:"Microsoft IIS MDAC RDS (msadcs.dll) Arbitrary Remote Command Execution");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a remote command execution 
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The web server is probably susceptible to a common IIS vulnerability 
discovered by 'Rain Forest Puppy'. This vulnerability enables an 
attacker to execute arbitrary commands on the server with 
Administrator Privileges. 

*** Nessus solely relied on the presence of the file /msadc/msadcs.dll
*** so this might be a false positive" );
 script_set_attribute(attribute:"see_also", value:"http://support.microsoft.com/default.aspx?scid=kb;[LN];184375" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms98-004" );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms99-025" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to MDAC version 2.1 SP2 or higher, as it has been reported to 
fix this vulnerability. It is also possible to correct the flaw by 
implementing the following workaround: Delete the /msadc virtual 
directory in IIS." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS99-025 Microsoft IIS MDAC msadcs.dll RDS Arbitrary Remote Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_cwe_id(264);

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/04/01");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/07/19");
 script_cvs_date("$Date: 2014/03/31 10:44:06 $");
script_xref(name:"MSFT", value: "MS98-004");
script_xref(name:"MSFT", value: "MS99-025");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determines the presence of msadcs.dll");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2014 Roelof Temmingh <roelof@sensepost.com>");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/iis", "Settings/ParanoidReport");
 exit(0);
}

#
# The script code starts here
#


include("http_func.inc");
include("http_keepalive.inc");
include("global_settings.inc");

if ( report_paranoia < 2 )
 exit(0, "This script only runs in 'paranoid' mode as it is prone to false positive.");

port = get_http_port(default:80);

b = get_http_banner(port: port);
if (! b) exit(1, "The HTTP banner on port "+port+" cannot be read.");
if ("IIS" >!< b) exit(0, "The web server on port "+port+" is not IIS.");

cgi = "/msadc/msadcs.dll";
res = is_cgi_installed_ka(item:cgi, port:port);
if(res)security_hole(port);
