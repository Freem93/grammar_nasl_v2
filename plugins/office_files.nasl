#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(11419);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2013/08/13 20:20:52 $");
 
 script_name(english:"Web Server Office File Inventory");
 script_summary(english:"Displays office files");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server hosts office-related files.");
 script_set_attribute(attribute:"description", value:
"This plugin connects to the remote web server and attempts to find
office-related files such as .doc, .ppt, .xls, .pdf etc.");
 script_set_attribute(attribute:"solution", value:
"Make sure that such files do not contain any confidential or otherwise
sensitive information and that they are only accessible to those with
valid credentials.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2003/03/19");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:microsoft:office");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2003-2013 Tenable Network Security, Inc.");
 script_family(english:"CGI abuses");

 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "webmirror.nasl", "no404.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


global_var	port;
global_var attachments;
global_var global_attachment_sz;
global_var MAX_ATTACHMENTS_SZ;


attachments = make_list();
global_attachment_sz = 0;
MAX_ATTACHMENTS_SZ = 5*1024*1024;

function sanitize_name()
{
 local_var name;

 name = _FCT_ANON_ARGS[0];
 if ( name == NULL ) 
   return NULL;

 return ereg_replace(pattern:"[^a-zA-Z0-9\.\_\-]", string:name, replace:"_");
}

function test_files(files)
{
 local_var	f, w, r, retf;
 local_var 	n;
 
 retf = make_list();
 foreach f (files)
 {
  w = http_send_recv3(method:"GET", item:f, port:port, exit_on_fail: 1);
  
  if(w[0] =~ "^HTTP/[0-9]\.[0-9] 200 ") {
  	retf = make_list(retf, f);
	if ( defined_func("nasl_level") && nasl_level() >= 5200 )
		{
		 if ( global_attachment_sz < MAX_ATTACHMENTS_SZ && strlen(w[2]) != _http_max_req_sz )
			{
			  n = max_index(attachments);
			  attachments[n] = make_array();
			  if ( f =~ "\.pdf$" )
			  	attachments[n]["type"] = "application/pdf";
			  else
			  	attachments[n]["type"] = "application/octet-stream";
				
			  attachments[n]["name"] = sanitize_name(ereg_replace(pattern:"^.*/([^/]*)$", string:f, replace:"\1"));
			  attachments[n]["value"] = w[2];
			  global_attachment_sz += strlen(w[2]);
			}
		}
	}
 }
 return retf;
}


port = get_http_port(default:80, embedded: 0);

report = "";

software["doc"] = "Word";
software["docx"] = "Word 2007";
software["docm"] = "Word 2007";
software["dotx"] = "Word 2007";
software["dotm"] = "Word 2007";
software["dot"] = "Word 2007";
software["xls"] = "Excel";
software["xlsx"] = "Excel 2007";
software["xlsm"] = "Excel 2007";
software["xlsb"] = "Excel 2007";
software["xltx"] = "Excel 2007";
software["xltm"] = "Excel 2007";
software["xlt"] = "Excel 2007";
software["xlam"] = "Excel 2007";
software["xla"] = "Excel 2007";
software["xps"] = "Excel 2007";
software["ppt"] = "PowerPoint";
software["pptx"] = "PowerPoint 2007";
software["pptm"] = "PowerPoint 2007";
software["potx"] = "PowerPoint 2007";
software["potm"] = "PowerPoint 2007";
software["pot"] = "PowerPoint 2007";
software["ppsx"] = "PowerPoint 2007";
software["ppsm"] = "PowerPoint 2007";
software["pps"] = "PowerPoint 2007";
software["ppam"] = "PowerPoint 2007";
software["ppa"] = "PowerPoint 2007";
software["wps"] = "MS Works";
software["wri"] = "Write";
software["csv"] = "CSV Spreadsheet";
software["dif"] = "DIF Spreadsheet";
software["rtf"] = "Rich Text Format / Word Processor";
software["pdf"] = "Adobe Acrobat";
software["sxw"] = "OO Writer";
software["sxi"] = "00 Presentation";
software["sxc"] = "00 Spreadsheet";
software["sdw"] = "StarWriter";
software["sdd"] = "StarImpress";
software["sdc"] = "StarCalc";
software["ods"] = "OpenDocument Spreadsheet";
software["odt"] = "OpenDocument Text";
software["odp"] = "OpenDocument Presentation";
software["odc"] = "OpenDocument";


foreach ext(sort(keys(software)))
{
 t = get_kb_list(string("www/", port, "/content/extensions/", ext));
if(!isnull(t)){
 t = test_files(files:make_list(t));
 word = NULL;
 foreach f (t)
 {
  word += '    ' + f + '\n';
 }
 if(word)
  report += '  - ' + software[ext] + ' files (.' + ext + ') :\n' + word + '\n';
 }
}

if (report)
{
 if (report_verbosity > 0)
 {
  report = 
    '\nThe following office-related files are available on the remote server :' +
    '\n' +
    '\n' + report;
  if ( !defined_func("nasl_level") || nasl_level() < 5200 || !isnull(get_preference("sc_version")) ) security_note(port:port, extra:report);
  else security_report_with_attachments(port:port, level:0, extra:report, attachments:attachments);
 }
 else security_note(port);
}
