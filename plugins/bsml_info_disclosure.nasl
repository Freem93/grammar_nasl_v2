#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(11973);
 script_bugtraq_id(9311);
 script_osvdb_id(50563);
 script_version ("$Revision: 1.17 $");
 script_name(english:"BulletScript MailList bsml.pl Information Disclosure");
 script_summary(english:"Check bml.pl for information disclosure");

 script_set_attribute( attribute:"synopsis", value:
"A web application running on the remote host has an information
disclosure vulnerability." );
 script_set_attribute( attribute:"description", value:
"The remote host is using BulletScript's bsml.pl, the web interface to
a mailing list manager.

The lack of authentication in this CGI may allow an attacker to gain
control on the email addresses database of the remote mailing list.
A remote attacker can manipulate the 'action' parameter of bsml.pl
to add or remove an email address, or to gather the list of
subscribers to the remote mailing list for spam purposes." );

 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to the latest version of BulletScript, or disable the script."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_set_attribute(attribute:"plugin_publication_date", value: "2004/01/01");
 script_cvs_date("$Date: 2016/06/10 20:49:25 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
 script_dependencie("find_service1.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

foreach d (make_list(cgi_dirs()))
{
 url = string(d, "/bsml.pl?action=sm");
 r = http_send_recv3(method:"GET", item:url, port:port);
 if (isnull(r)) exit(0);
 buf = strcat(r[0], r[1], '\r\n', r[2]);
 if ("/bsml.pl?action=empty" >< buf ) { security_warning(port); exit(0); }
}
