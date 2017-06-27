##
# CVS directory spider 
# --------------------
#
# If a /CVS directory has been found, this plugin uses the standard 
# CVS/Entries file to discover additional directories. 
#
# Author: R. Boon (r.boon@itsec.nl)
#

# Changes by Tenable:
# - Revised plugin title (12/22/2008)

include("compat.inc");

if (description)
{
  script_id(25758);
  script_version("$Revision: 1.15 $");

  script_name(english:"CVS (Web-Based) Directory Spider");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server may be affected by an information disclosure
vulnerability." );
 script_set_attribute(attribute:"description", value:
"The CVS directory contains the standard CVS file 'Entries'. 

Using this file, part of the contents of the document root of the
web server can be obtained.  This allows an attacker to search for
sensitive information located in the document root of the web server." );
 script_set_attribute(attribute:"solution", value:
"Do not place the CVS-directory in the document root.  Use the CVS
export function to create deployable code." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value: "2007/07/24");
 script_cvs_date("$Date: 2015/10/13 15:19:32 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

  script_summary(english:"Enumerates the document root using the CVS Entries file");
  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");
  script_copyright("This script is (C) 2007-2015 R. Boon (r.boon@itsec.nl)");
  script_dependencies("DDI_Directory_Scanner.nasl", "webmirror.nasl", "http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 80);
  
  exit(0);
}

# Script code starts here
#
include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");


# nb: only run this if the "Perform thorough tests" setting is enabled because it may generate a
#     large number of requests.
if (!thorough_tests) exit(0);


function get_entries_file(path, port)
{
	local_var req, res;

	res = is_cgi_installed_ka(item:string(path, "CVS/Entries"), port:port) ;

	if (res)
	{
		req = http_get(port:port, item:string(path, "CVS/Entries"));
		res = http_keepalive_send_recv(port:port, data:req, bodyonly:TRUE);
		return res;
	}

	return res;

}

function get_directory_list(path, entry_content)
{
	local_var d, dirlist, dname, lines_with_d, list;

	if (entry_content)
	{
		lines_with_d = egrep(string:entry_content, pattern:"^D.*");

		dirlist = split(lines_with_d, "D");

		foreach d (dirlist)
		{
			# cut out the directory
			# line is D/<dirname>////
			dname = split(d, sep:string("/"));
			
			if (!isnull(dname[1]))
			{
				if (!isnull(list))
				{
					list = make_list(list, string(path, dname[1]));
				}
				else
				{
					list = make_list(string(path, dname[1]));
				}
			}
		}
	}
	return list;
}

# function is called when there is a CVS dir
function cvs_directory_spider(path, port)
{
	local_var d, dirs, dirs_new, ret;

	dirs = get_directory_list(path:path, entry_content:get_entries_file(path:path, port:port));

	if (isnull(dirs))
	{
		return NULL;
	}
	else
	{
		ret = make_list(dirs);
			
		foreach d (dirs)
		{
			dirs_new = cvs_directory_spider(path:d, port:port);

			if (!isnull(dirs_new))
			{
				ret = make_list(ret, dirs_new);
			}

		}
	}
	return ret;
}

port = get_http_port(default:80);
if(!port || !get_port_state(port)) exit(0);

# Check for CVS dir
dirs = get_kb_list(string("www/", port, "/content/directories"));

if (isnull(dirs))
{
	exit(0, "No directory found.");
}

count = 0;
foreach d (dirs)
{
	if ("/CVS" >< d)
	{
		count++;
	}
}

if (count == 0)
{
	exit(0, "No CVS directory found.");
}

ndirs = cvs_directory_spider(path:string("/"), port:port);
if (isnull(ndirs)) exit(0);

result = "Using the 'CVS/Entries' file the following directories can be found : " + '\n\n';

foreach d (ndirs)
{
	result = result + string("  ", d, "\n");
}

result = 
  '\n' +
  result + 
  "Note that the 'Entries' files also contain descriptive filenames of" + '\n' +
  "files that may contain sensitive information.";

security_warning(port:port, extra:result);
