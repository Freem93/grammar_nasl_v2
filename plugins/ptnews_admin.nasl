#
# (C) Tenable Network Security, Inc.
#



include("compat.inc");

if (description)
{
 script_id(11589);
 script_bugtraq_id(7394);
 script_version ("$Revision: 1.13 $");

 script_name(english:"PT News Unauthorized Administrative Access");
 script_set_attribute(attribute:"synopsis", value:
"Information managed by the remote service can be modified or erased." );
 script_set_attribute(attribute:"description", value:
"The remote host is using the PT News management system.

There is a flaw in this version which allows anyone to execute arbitrary
admnistrative PTnews command on this host (such as deleting news or 
editing a news) without having to know the administrator password.

An attacker may use this flaw to edit the content of this website or 
even to delete it completely." );
 script_set_attribute(attribute:"solution", value:
"Upgrade to PT News 1.7.8 or newer." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/07");
 script_cvs_date("$Date: 2011/03/14 21:48:11 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english:"Determine if PTNews grants administrative access to everyone");
 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 script_dependencie("webmirror.nasl", "http_version.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_keys("www/PHP");
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80, embedded: 0);
if(!can_host_php(port:port))exit(0);

dirs = list_uniq(make_list("/ptnews", cgi_dirs()));
		
foreach d (dirs)
{
 rnd = rand();
 
 url = string(d, "/index.php?edit=nonexistant", rnd);
 r = http_send_recv3(method: "GET", item:url, port:port);
 if (isnull(r)) exit(0);
 if(egrep(pattern:"./nonexistant" + rnd + " .*/news.inc", string: r[1]+r[2]))
   {
    security_warning(port);
    exit(0);
   }
}
