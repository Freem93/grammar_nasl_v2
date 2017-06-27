#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");


if (description)
{
 script_id(12245);
 script_version("$Revision: 1.16 $");
 script_cvs_date("$Date: 2015/09/24 21:17:10 $");
 
 script_name(english:"Java (.java / .class) Source Code Disclosure");
 script_summary(english:"Java Source Code Disclosure check");

 script_set_attribute(attribute:"synopsis", value:"The remote web server is disclosing potentially sensitive data.");
 script_set_attribute(attribute:"description", value:
"The remote web server is hosting Java (.java and/or .class) files. 
These files may contain sensitive or proprietary information.  If so, a
remote attacker could use this information to mount further attacks.");
 script_set_attribute(attribute:"solution", value:"Restrict access to any sensitive data.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2004/05/20");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"CGI abuses");

 script_copyright(english:"This script is Copyright (C) 2004-2015 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "webmirror.nasl", "http_version.nasl");
 script_exclude_keys("Settings/disable_cgi_scanning");
 script_require_ports("Services/www", 80);
 exit(0);
}

# start script

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

init = get_kb_list(string("www/", port, "/java_classfile"));

if (isnull(init)) 
	exit(0);


master = make_list(init);
mylist = make_list();


# Ensure that web server doesn't respond with '200 OK' for everything

u = strcat("/", rand_str(), ".class"); 
w = http_send_recv3(method:"GET", item: u, port:port);
if (isnull(w)) exit(1, "The web server did not answer");
if ("200 OK" >< w[1]) exit(0);


vcounter = 0;

ext_l = make_list(".java", ".class");

foreach script (master) 
{
    if ( (".class" >< tolower(script)) || (".java" >< tolower(script)) ) 
    {
        rootname = ereg_replace(string:script, pattern:"\.class|\.java", replace:"", icase:TRUE);
    } 
    else 
    {
        rootname = script;
    }

    if ("http://" >< rootname) continue;

    foreach e (ext_l)
    {
      u = string(rootname, e);
      w  = http_send_recv3(method:"GET", item:u, port:port);
      if (isnull(w)) exit(1, "The web server did not answer");

      if (w[0] =~ "^HTTP/.* 200 OK")
      {
	mylist = make_list(mylist, u);
	vcounter++;
      }
    }

    if (vcounter > 20) 
	break;        
}

if (vcounter) 
{
    report = string("\nNessus was able to download the following files :\n\n");

    foreach file (mylist) 
        report += string(file,"\n");

    security_warning(port:port, extra:report);
}




