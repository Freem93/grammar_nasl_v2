#
# Copyright 2000 by Hendrik Scholz <hendrik@scholz.net>
#
# @DEPRECATED@
#
# Disabled on 2016/04/01. Webmirror3.nbin will identify browsable
# directories.

include("compat.inc");

if(description)
{
 script_id(10056);
 script_version ("$Revision: 1.29 $");
 script_cvs_date("$Date: 2016/12/30 22:07:39 $");

 script_cve_id("CVE-1999-0678");
 script_bugtraq_id(318);
 script_osvdb_id(48);

 script_name(english:"/doc Directory Browsable (deprecated)");
 script_summary(english:"Checks if /doc browsable.");

 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"The /doc directory is browsable. /doc shows the contents of the
/usr/doc directory, which reveals not only which programs are
installed but also their versions.

This plugin has been deprecated. Webmirror3 (plugin ID 10662) will
identify a browsable directory.");
 script_set_attribute(attribute:"see_also", value:"http://projects.webappsec.org/w/page/13246922/Directory%20Indexing");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"vuln_publication_date", value: "1999/04/05");
 script_set_attribute(attribute:"plugin_publication_date", value:"2000/01/03");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2000-2016 Hendrik Scholz");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

# Deprecated.
exit(0, "This plugin has been deprecated. Webmirror3 (plugin ID 10662) will identify a browsable directory.");

#
# The script code starts here

include("http_func.inc");
include("http_keepalive.inc");

port = get_http_port(default:80);

data = http_get(item:"/doc/", port:port);
buf = http_keepalive_send_recv(port:port, data:data);
if (isnull(buf)) exit(0);

buf = tolower(buf);
must_see = "index of /doc";

if((ereg(string:buf, pattern:"^http/[0-9]\.[0-9] 200 "))&&(must_see >< buf)){
   	security_warning(port);
	set_kb_item(name:"www/doc_browseable", value:TRUE);
	set_kb_item( name: 'www/'+port+'/content/directory_index',
		     value: '/doc/' );
}

