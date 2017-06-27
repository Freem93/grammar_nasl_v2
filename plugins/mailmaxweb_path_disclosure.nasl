#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11601);
 script_version ("$Revision: 1.14 $");
 script_osvdb_id(51865);

 script_name(english:"MailMaxWeb Cookie Application Path Disclosure");
 script_summary(english:"Checks for MailMaxWeb");
 
 script_set_attribute( attribute:"synopsis",  value:
"The webmail application running on the remote host has an
information disclosure vulnerability." );
 script_set_attribute( attribute:"description",   value:
"The remote server is running MailMaxWeb, a webmail application.

The version running on the remote host stores the absolute path
of this install in the cookie.  A remote attacker could use
this information to mount further attacks." );
  # http://web.archive.org/web/20090327223205/http://www.cirt.dk/advisories/cirt-12-advisory.txt
 script_set_attribute(
   attribute:"see_also",
   value:"http://www.nessus.org/u?e3c73acb"
 );
 script_set_attribute(
   attribute:"solution", 
   value:"There is no known solution at this time."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2012/09/27 02:49:21 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 
 script_copyright(english:"This script is Copyright (C) 2003-2012 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");

 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

init_cookiejar();

foreach d (cgi_dirs())
{
 if (! isnull(get_http_cookie(name: "IX"))) clear_cookiejar();
 r = http_send_recv3(method: "GET", item:d+"/", port:port);
 if (isnull(r)) exit(0);
 if (get_http_cookie(name: "IX"))
 {
  if (egrep(pattern:".*value=.[A-Za-z]:\\", string: r[1]+r[2]))
  	{
	security_warning(port);
	exit(0);
	}
 }
}
