#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11778);
 script_version("$Revision: 1.25 $");
 script_cvs_date("$Date: 2011/03/18 18:07:04 $");

 script_name(english:"Web Server Potentially Hosting Copyrighted Material");
 script_summary(english:"Looks for *.(mp3,avi,asf,mpg,wav,ogg)");

 script_set_attribute(
   attribute:"synopsis",
   value:"The remote web server appears to be hosting copyrighted media."
 );
 script_set_attribute(attribute:"description",  value:
"The remote web server is hosting media (mp3, wav, avi, or asf files)
that might be infringing on the owners' copyright." );
 script_set_attribute(
   attribute:"solution", 
   value:"Make sure the web server is authorized to host the given files."
 );
 script_set_attribute(
   attribute:"risk_factor", 
   value:"None"
 );
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/06/26");
 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

function check(port, sfx)
{
 local_var list;

 list = get_kb_list(string("www/", port, "/content/extensions/", sfx));
 if(isnull(list))return make_list();
 else list = make_list(list);
 return list;
}


 
port = get_http_port(default:80);

files = make_list();
files = make_list(files, check(port:port, sfx:"mp3"));
files = make_list(files, check(port:port, sfx:"MP3"));
files = make_list(files, check(port:port, sfx:"asf"));
files = make_list(files, check(port:port, sfx:"ASF"));
files = make_list(files, check(port:port, sfx:"mpg"));
files = make_list(files, check(port:port, sfx:"MPG"));
files = make_list(files, check(port:port, sfx:"mpeg"));
files = make_list(files, check(port:port, sfx:"MPEG"));
files = make_list(files, check(port:port, sfx:"ogg"));
files = make_list(files, check(port:port, sfx:"OGG"));
files = make_list(files, check(port:port, sfx:"vob"));
files = make_list(files, check(port:port, sfx:"VOB"));
files = make_list(files, check(port:port, sfx:"wma"));
files = make_list(files, check(port:port, sfx:"WMA"));
files = make_list(files, check(port:port, sfx:"torrent"));

report = NULL;

num_suspects = 0;
foreach f (files)
{
 if( strlen(f) )
 	{
	 report += ' - ' + f + '\n';
	 num_suspects ++;
	 if( num_suspects >= 40 )
	 { 
	  report += ' - ... (more) ...\n';
	  break;
	 }
	}
}

if (!isnull(report))
{
 r = '
Here is a list of files which have been found on the remote web server.
Some of these files may contain copyrighted materials, such as commercial
movies or music files. 

If any of this file actually contains copyrighted material and if
they are freely swapped around, your organization might be held liable
for copyright infringement by associations such as the RIAA or the MPAA.

' + report;

 security_note(port:port, extra:r);
}
