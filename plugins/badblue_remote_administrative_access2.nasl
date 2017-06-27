#
# (C) Tenable Network Security, Inc.
#

# XXX Could not reproduce the issue with BadBlue 2.2...
#
# Ref:
#  From: "mattmurphy@kc.rr.com" <mattmurphy@kc.rr.com>
#  To: bugtraq@securityfocus.com
#  Subject: BadBlue Remote Administrative Interface Access Vulnerability
#  Date: Tue, 20 May 2003 16:43:53 -0400


include("compat.inc");

if(description)
{
 script_id(11641);
 script_version ("$Revision: 1.12 $");
 script_osvdb_id(55173);
 script_cvs_date("$Date: 2016/10/07 13:30:46 $");

 script_name(english:"BadBlue ISAPI Extension ext.dll LoadPage Parameter Arbitrary File Access");
 script_summary(english:"Get the version of the remote BadBlue server");

 script_set_attribute(attribute:"synopsis", value:
"The web server is affected by an authentication bypass vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running BadBlue web server earlier then 2.3. Such
versions are reportedly affected by an authentication bypass
vulnerability. A flaw in the order that security checks are performed
could allow an attacker to gain administrative access to the
application." );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2003/Apr/251" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to BadBlue v 2.3 or newer as this reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/20");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
 script_category(ACT_ATTACK);
 
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");
 script_require_ports("Services/www", 80);
 script_dependencies("find_service1.nasl", "http_version.nasl");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

banner = get_http_banner(port:port);
if(!banner)exit(0);

vulnerable = egrep(pattern:"^Server: BadBlue/(1\.|2\.[0-2])", string:banner);
if(vulnerable)security_hole(port);


