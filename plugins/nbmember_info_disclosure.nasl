#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15542);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2004-2732");
  script_bugtraq_id(11504);
  script_osvdb_id(10902);

  script_name(english:"Netbilling nbmember.cgi cmd Parameter Information Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary files may be read on the remote host." );
 script_set_attribute(attribute:"description", value:
"nbmember.cgi is installed on the remote host.

The remote version of this software is vulnerable to an information 
disclosure flaw which may allow an attacker to access sensitive system
information resulting in a loss of confidentiality." );
 script_set_attribute(attribute:"solution", value:
"None at this time" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(78);

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/21");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/10");
 script_cvs_date("$Date: 2011/11/28 21:39:46 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_summary(english:"Checks for nbmember.cgi");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  exit(0);
}

# the code!

include("http_func.inc");
include("http_keepalive.inc");


port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!get_port_state(port)) exit(0);

function check(req)
{
  local_var buf, r;

  buf = http_get(item:string(req,"/nbmember.cgi?cmd=test"), port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"Version.*Config file.*Password file.*Password file exists.*Password file is readable.*Password file is writable.*SERVER_SOFTWARE ", string:r))
  {
 	security_warning(port);
	exit(0);
  }
}

foreach dir (cgi_dirs()) check(req:dir);
