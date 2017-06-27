#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(24245);
 script_version("$Revision: 1.22 $");

 script_cve_id("CVE-2006-3436");
 script_bugtraq_id(20337);
 script_xref(name:"OSVDB", value:"29431");

 script_name(english:"MS06-056: Vulnerabilities in ASP.NET could allow information disclosure (922770) (uncredentialed check)");
 script_summary(english:"Determines the version of the ASP.Net DLLs via HTTP");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote .Net Framework is vulnerable to a cross-site scripting
attack." );
 script_set_attribute(attribute:"description", value:
"The remote host is running a version of the ASP.NET framework affected
by a cross-site scripting vulnerability that could allow an attacker
to execute arbitrary code in the browser of the users visiting the
remote website." );
 script_set_attribute(attribute:"solution", value:
"Microsoft has released a set of patches for Windows 2000, XP and 
2003 :

http://technet.microsoft.com/en-us/security/bulletin/ms06-056" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/01/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/10/10");
 script_cvs_date("$Date: 2015/02/13 21:07:15 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2006/10/10");
 script_xref(name:"MSFT", value: "MS06-056");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:.net_framework");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"Windows");
 script_dependencies("dotnet_framework_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

ver = get_kb_item("www/" + port + "/ASP.NET_Version");
if ( ! ver ) exit(0);

v = split(ver, sep:'.', keep:FALSE);
for ( i = 0 ; i < max_index(v) ; i ++ ) v[i] = int(v[i]);

if ( ! isnull(v) ) 
       if ( (v[0] == 2 && v[1] == 0 && v[2] == 50727 && v[3] < 210 ) )
{
 security_warning(port);
 set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
}

