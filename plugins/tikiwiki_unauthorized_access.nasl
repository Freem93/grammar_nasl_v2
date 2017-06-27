#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(14359);
 script_version("$Revision: 1.14 $");
 script_cvs_date("$Date: 2014/08/09 00:11:25 $");
 script_bugtraq_id(10972);

 script_name(english:"TikiWiki Unauthorized Page Access");
 script_summary(english:"Checks the version of TikiWiki");

 script_set_attribute(attribute:"synopsis", value:
"The remote host has a PHP script that could allow
unauthorized access to certain restricted pages." );
 script_set_attribute(attribute:"description", value:
"The remote host is running TikiWiki, a content management
system written in PHP.

The remote version of this software is vulnerable to a
flaw that could allow an attacker to bypass the permissions
of individual Wiki pages.

An attacker could exploit this flaw to deface the remote web
server or gain access to pages where access should be denied." );
 script_set_attribute(attribute:"solution", value:"Upgrade to TikiWiki 1.8.4.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/08/23");

script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe", value:"cpe:/a:tikiwiki:tikiwiki");
script_end_attributes();


 script_category(ACT_GATHER_INFO);

 script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("tikiwiki_detect.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP","www/tikiwiki");
 exit(0);
}

#
# The script code starts here
#
include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

port = get_http_port(default:80,php:TRUE);

function check(loc)
{
 local_var res;
 res = http_send_recv3(method:"GET", item:loc + "/tiki-index.php", port:port);
 if(isnull(res))exit(0);
 if( egrep(pattern:"This is Tiki v(0\.|1\.[0-7]\.|1\.8\.[0-3][^0-9])", string:res[2]) )
 {
   security_warning(port);
   exit(0);
 }
}

install = get_install_from_kb(appname:'tikiwiki', port:port, exit_on_fail:TRUE);
dir = install['dir'];

check(loc:dir);

