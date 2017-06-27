#
# (C) Tenable Network Security, Inc.
#

# Ref:
#
# From: "BrainRawt ." <brainrawt@hotmail.com>
# To: bugtraq@securityfocus.com
# Subject: CGI-City's CCGuestBook Script Injection Vulns
# Date: Sat, 29 Mar 2003 18:47:04 +0000


include("compat.inc");

if(description)
{
 script_id(11503);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2003-1556");
 script_bugtraq_id(7237);
 script_osvdb_id(44165);

 script_name(english:"CC GuestBook cc_guestbook.pl Multiple Parameter XSS");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Perl script is affected by a cross-
site scripting vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running cc_guestbook.pl, a guestbook written in
Perl. 

This CGI is vulnerable to a cross-site scripting attack.  An attacker
may use this flaw to steal the cookies of your users." );
 script_set_attribute(attribute:"solution", value:
"Delete this CGI." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(79);

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/30");
 script_cvs_date("$Date: 2011/03/14 21:48:02 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Checks for the presence of view.php");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses : XSS");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
# The script code starts here
#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if(!get_port_state(port))exit(0);



foreach dir ( cgi_dirs() )
{
 r = http_send_recv3(port:port, method: 'GET', item: strcat(dir, "/cc_guestbook.pl"));

 if (isnull(r)) exit(0);

 if("Please enter a valid email address" >< r[2] &&
    "Please enter your homepage title" >< r[2])
 	{
	security_warning(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
	exit(0);
	}
}
