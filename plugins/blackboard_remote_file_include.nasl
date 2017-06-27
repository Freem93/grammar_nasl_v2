#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(15450);
  script_version("$Revision: 1.17 $");

  script_cve_id("CVE-2004-1582");
  script_bugtraq_id(11336);
  script_osvdb_id(10538);

  script_name(english:"BlackBoard Internet Newsboard System checkdb.inc.php libpath Parameter Remote File Inclusion");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbritrary code may be run on the remote host." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the BlackBoard Internet Newsboard System,
an open source, PHP-based internet bulletin board software application.

The remote version of this software is vulnerable to a remote file
include flaw in checkdb.inc.php, due to a lack of sanitization of 
user-supplied data to the 'libpath' parameter.

Successful exploitation of this issue may allow an attacker to execute 
malicious script code on a vulnerable server.

*** Nessus reports this vulnerability using only
*** information that was gathered. Therefore,
*** this might be a false positive." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the newest version of this software." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2004/10/11");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/10/06");
 script_cvs_date("$Date: 2012/11/29 23:28:09 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:blackboard_internet_newsboard_system:blackboard_internet_newsboard_system");
script_end_attributes();


  script_summary(english:"Checks BlackBoard Internet Newsboard System version");
  script_category(ACT_GATHER_INFO);
  
  script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_dependencies("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);
if ( ! port ) exit(0);
if(!can_host_php(port:port))exit(0);

if(get_port_state(port))
{
  buf = http_get(item:"/forum.php", port:port);
  r = http_keepalive_send_recv(port:port, data:buf, bodyonly:1);
  if( r == NULL )exit(0);
  if(egrep(pattern:"<title>BlackBoard Internet Newsboard System</title>.*BlackBoard.*(0\.|1\.([0-4]|5[^.]|5\.1[^-]|5\.1-[a-g]))", string:r))
  {
    security_hole(port);
  }
}
exit(0);
