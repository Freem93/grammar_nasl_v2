#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(18522);
 script_version ("$Revision: 1.15 $");
 script_cve_id("CVE-2005-2008");
 script_bugtraq_id(13981);
 script_osvdb_id(17375);

 script_name(english:"Yaws Web Server .yaws Script Null Byte Request Source Code Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the Yaws web server. 

The remote version of this software is vulnerable to a source code
disclosure issue.  By requesting a '.yaws' script following by %00, an
attacker may force the remote server to disclose the source code of
that script. 

Since scripts may contain sensitive information such as logins and
passwords, an attacker may exploit this flaw to obtain some
credentials on the remote host or a better understanding of the
security of the '.yaws' scripts." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=111927717726371&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to YAWS 1.56 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/06/17");
 script_cvs_date("$Date: 2011/03/13 23:54:24 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 summary["english"] = "Downloads the source of .yaws scripts";
 script_summary(english:summary["english"]);
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var	port;

function check(file)
{
  local_var	r;

  r = http_send_recv3(item:string(file, "%00"), method:"GET", port:port,
    exit_on_fail: 1);
  if("<erl>" >< r[2] && "</erl>" >< r[2] )
	{
  	security_warning(port);
	exit(0);
	}
}


port = get_http_port(default:80);
banner = get_http_banner(port:port);
if ( "Server: Yaws/" >< banner ) {
  files = get_kb_list(string("www/", port, "/content/extensions/yaws"));
  if(isnull(files))exit(0);
  files = make_list(files);
  check(file:files[0]); 
}
