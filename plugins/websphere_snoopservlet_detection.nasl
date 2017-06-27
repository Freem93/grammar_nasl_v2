#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(23639);
 script_version("$Revision: 1.12 $");
 script_cvs_date("$Date: 2015/10/21 20:34:21 $");

 script_osvdb_id(54236);
 
 script_name(english:"IBM WebSphere snoopservlet Path Disclosure");
 script_summary(english:"Attempts to enumerate physical path");

 script_set_attribute(attribute:"synopsis", value:
"The remote web server is affected by an information disclosure flaw.");
 script_set_attribute(attribute:"description", value:
"This script attempts to enumerate the actual physical path of the
servlet classes by requesting a version of 'snoopservlet' which is
missing required classes.  An attacker, gaining information about the
actual physical layout of the file system, can use the information in
crafting more complex attacks.");
 script_set_attribute(attribute:"solution", value:
"If not required, uninstall the default applications.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2006/11/14");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:websphere_application_server");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2006-2015 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("find_service1.nasl", "webmirror.nasl", "http_version.nasl", "DDI_Directory_Scanner.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

files = make_list("SnoopServlet", "snoopservlet", "snoop");

port = get_http_port(default:80);

dirs = get_kb_list(string("www/", port, "/content/directories"));
if (isnull(dirs)) dirs = make_list();
dirs = list_uniq(make_list(dirs, "", "/servlet"));

totalcounter = 0;
foreach d (dirs)
{
	foreach f (files)
	{
		u = strcat(d,"/",f,"/");
		r = http_send_recv3(method: "GET", item: u, port:port);
		if ( "servlet was originally compiled with classes which cannot be located by the server" >< r[2] ||
		     "<tr><td>javax.servlet.context.tempdir</td><td>/" >< r[2] ||
		     egrep(string:r[2], pattern:"classpath=\[[a-zA-Z]:\\.*\.jar")  )
		{
			report = strcat(
			'The following file, when requested, will leak information\n',
			'regarding the local configuration :\n\n',
			build_url(port: port, qs: u), '\n');
			security_warning(port:port, extra: report);
			if (COMMAND_LINE) display(report);
			exit(0);
		}
	}
}
