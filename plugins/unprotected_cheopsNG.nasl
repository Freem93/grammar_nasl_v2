#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(20161);
 script_version ("$Revision: 1.9 $");
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");
 script_name(english:"Cheops NG Unauthenticated Access");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service does not require a password for access." );
 script_set_attribute(attribute:"description", value:
"The Cheops NG agent on the remote host is running without
authentication.  Anyone can connect to this service and use it to map
your network, port scan machines and identify running services." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to this port or enable authentication by starting the
agent using the '-p' option." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/08");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Cheops NG agent is running without authentication");
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english:"Misc.");
 script_dependencie("cheopsNG_detect.nasl");
 script_require_keys("cheopsNG/unprotected");
 exit(0);
}

#

port = get_kb_item("cheopsNG/unprotected");
if (port) security_warning(port);
