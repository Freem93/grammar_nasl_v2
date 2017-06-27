# 
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(11682);
 script_version ("$Revision: 1.16 $");
 script_osvdb_id(52991);
 script_cvs_date("$Date: 2013/01/25 01:19:09 $");

 
 script_name(english:"Philboard /database/philboard.mdb Direct Request Database Disclosure");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that is affected by an
information disclosure vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Philboard. It is possible to download
the database of this server (philboard.mdb) and to obtain
valuable information from it (passwords, archives, and so on)." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/323224" );
 script_set_attribute(attribute:"solution", value:
"Prevent the download of .mdb files from your web server." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/02");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_summary(english:"Downloads philboard.mdb");
 
 script_category(ACT_GATHER_INFO);
 
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");
 script_dependencie("find_service1.nasl", "http_version.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

# The script code starts here

include("global_settings.inc");
include("misc_func.inc"); 
include("http.inc");

port = get_http_port(default:80, embedded: 0);

function check(loc)
{
 local_var req, res;
 res = http_send_recv3(port:port, method:"GET", item:loc);
 if(isnull(res)) exit(1, "Null response for '"+ loc + "' request.");

 if("Standard Jet DB" >< res[2]) 
  security_warning(port); 
  exit(0); 
}

dirs = list_uniq(make_list("/forum", cgi_dirs()));

foreach dir (dirs)
 check(loc: dir + "/database/philboard.mdb");		
