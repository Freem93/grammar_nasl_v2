#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(14810);
 script_version ("$Revision: 1.21 $");
 script_cve_id("CVE-2004-0646", "CVE-2004-0928", "CVE-2004-1477", "CVE-2004-1478", "CVE-2004-2182");
 script_bugtraq_id(11245, 11331, 11411, 11413, 11414);
 script_osvdb_id(10238, 10239, 10240, 10546, 19753);

 script_name(english:"JRun Multiple Vulnerabilities (OF, XSS, ID, Hijacking)");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web application server is affected by multiple flaws." );
 script_set_attribute(attribute:"description", value:
"The remote host is running JRun, a J2EE application server running on
top of IIS or Apache.  There are multiple flaws in the remote version
of this software :

 - The JSESSIONID variable is not implemented securely. An attacker may
   use this flaw to guess the session id number of other users. Only
   JRun 4.0 is affected.

 - There is a code disclosure issue that may allow an attacker to obtain
   the contents of a .cfm file by appending ';.cfm' to the file name.
   Only the Microsoft IIS connector and JRun 4.0 are affected.

 - There is a buffer overflow vulnerability if the server connector is 
   configured in 'verbose' mode. An attacker may exploit this flaw to 
   execute arbitrary code on the remote host." );
 script_set_attribute(attribute:"see_also", value:"http://www.acrossecurity.com/papers/session_fixation.pdf" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?10a5f865" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?60f8f589" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/mpsb04-08.html" );
 script_set_attribute(attribute:"see_also", value:"http://www.macromedia.com/devnet/security/security_zone/mpsb04-09.html" );
 script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch / updater referenced in the vendor
advisories above." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(287);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/09/24");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/09/23");
 script_cvs_date("$Date: 2011/10/14 21:48:33 $");
 script_set_attribute(attribute:"patch_publication_date", value: "2004/09/23");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"downloads the source of CFM scripts");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "www_fingerprinting_hmap.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(file, port)
{
  local_var r, w;

  file = str_replace(find:".cfm", replace:";.cfm", string:file);
  w = http_send_recv3(method:"GET", item:file, port:port);
  if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
  r = strcat(w[0], w[1], '\r\n', w[2]);
  r = tolower(r);
  if ( egrep(pattern:"< *(cfinclude|cfset|cfparam)", string:r) )
	{
  	security_warning(port);
	return(1);
	}
 return(0);
}

port = get_http_port(default:80);
banner = get_http_banner(port:port);

if( banner && "JRun" >< banner )
{
 if(check(file:"/index.cfm", port:port))exit(0);
 files = get_kb_list(string("www/", port, "/content/extensions/cfm"));
 if(isnull(files))exit(0);
 files = make_list(files);
 check(file:files[0], port:port);
}
