#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16178);
  script_version("$Revision: 1.15 $");

  script_cve_id("CVE-2005-0380");
  script_bugtraq_id(12258);
  script_osvdb_id(12928, 12929, 12930, 12931, 12932);
  
  script_name(english:"ZeroBoard Multiple Scripts dir Parameter Remote File Inclusion");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains several PHP scripts that are prone to
arbitrary PHP code execution and file disclosure attacks." );
 script_set_attribute(attribute:"description", value:
"The remote host runs Zeroboard, a web BBS application popular in Korea. 

The remote version of this CGI is vulnerable to multiple flaws which may
allow an attacker to execute arbitrary PHP commands on the remote host
by including a PHP file hosted on a third-party server, or to read
arbitrary files with the privileges of the remote web server." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=110565373407474&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to Zeroboard 4.1pl6 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:W/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/01/17");
 script_set_attribute(attribute:"vuln_publication_date", value: "2005/01/13");
 script_cvs_date("$Date: 2011/11/28 21:39:47 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Checks for Zeroboard flaws");
  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");
  script_require_ports("Services/www", 80);
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_dependencie("http_version.nasl");
  script_require_keys("www/PHP");
  exit(0);
}

#the code

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");
include("misc_func.inc");

port = get_http_port(default:80);
if (get_kb_item("Services/www/"+port+"/embedded")) exit(0);
if ( ! can_host_php(port:port) ) exit(0);

if (thorough_tests) dirs = list_uniq(make_list("/bbs", cgi_dirs()));
else dirs = make_list(cgi_dirs());

foreach dir (dirs) {
 req = http_get(item:string(dir, "/_head.php?_zb_path=../../../../../../../../../../etc/passwd%00"), port:port);
 res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
 if(isnull(res)) exit(0);
 if(egrep(pattern:"root:.*:0:[01]:", string:res)){
        security_hole(port);
        exit(0);
        }
}
