#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(17653);
 script_cve_id("CVE-2005-0948", "CVE-2005-0949");
 script_bugtraq_id(12936);
 script_osvdb_id(15119, 15120, 15158, 15159);
 script_version("$Revision: 1.15 $");
 script_name(english:"ASP PortalApp Multiple SQL Injection");
 
 script_set_attribute(attribute:"synopsis", value:
"A remote web application is vulnerable to several flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running ASP PortalApp, a web application software
written in ASP.

There is a flaw in the remote software that could allow anyone to inject
arbitrary SQL commands, which could in turn be used to gain administrative
access on the remote host.

In addition, a path disclosure and cross-site scripting vulnerability
were reported, although Nessus has not checked for them." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/30");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/03/30");
 script_cvs_date("$Date: 2015/12/15 17:46:19 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "SQL Injection");
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
 family["english"] = "CGI abuses";
 script_family(english:family["english"]);
 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("www/ASP");
 exit(0);
}

# Check starts here

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);

if (! can_host_asp(port:port)) exit(0);


function check(dir)
{
  local_var buf, r;
  r = http_send_recv3(method: "GET", item:dir + "/ad_click.asp?banner_id='", port:port);
  if (isnull(r)) exit(0);
  buf = r[0]+r[1]+'\r\n'+r[2];
  if("Microsoft JET"  >< buf && '80040e14' >< buf  )
  	{
	security_hole(port);
	set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
 
 
 return(0);
}

check( dir:"");
