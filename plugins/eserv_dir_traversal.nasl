#
# (C) Tenable Network Security, Inc.
#

# Ref: 
# Date: Wed, 21 May 2003 19:40:00 -0700
# From: D4rkGr3y <grey_1999@mail.ru>
# To: bugtraq@security.nnov.ru, bugtraq@securityfocus.com
# Subject: EServ/2.99: problems


include("compat.inc");


if(description)
{
 script_id(11656);
 script_version ("$Revision: 1.17 $");
 script_bugtraq_id(7669);
 script_osvdb_id(57668);
 script_xref(name:"Secunia", value:"8867");
 
 script_name(english:"Eserv Web Server /? Request Forced Directory Listing");
 script_summary(english:"GET /?");
 
 script_set_attribute( attribute:"synopsis", value:
"The web server running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute( attribute:"description",  value:
"The version of EServ running on the remote host is vulnerable to an
information disclosure attack.  Sending a specially crafted GET
request returns a directory listing, even when an index file is
present.

A remote attacker could use this information to mount further attacks
against the system." );
 script_set_attribute(
   attribute:"see_also",
   value:"http://seclists.org/bugtraq/2003/May/255"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of EServ."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/27");
 script_cvs_date("$Date: 2016/11/15 13:39:09 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");
 script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if('a href="./"' >< res && 'a href="../"' >< res)exit(0);
 
res = http_send_recv3(method:"GET", item:"/?", port:port, exit_on_fail: 1);

if('a href="./"' >< res[2] && 'a href="../"' >< res[2])security_warning(port);
