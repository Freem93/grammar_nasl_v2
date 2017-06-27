#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description) 
{
  script_id(52658);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/09/19 17:01:44 $");

  script_name(english:"IBM Sametime Detection");
  script_summary(english:"Detects the Sametime version Information.");

  script_set_attribute(attribute:"synopsis", value:
"A collaboration application is running on the remote web server.");
  script_set_attribute(attribute:"description", value:
"IBM Sametime, a web conferencing, instant messaging, and scheduling
application, is running on the remote web server.

Note that IBM Sametime was formerly known as Lotus Sametime.");
  script_set_attribute(attribute:"see_also", value:"http://www-03.ibm.com/software/products/en/ibmsame");
  script_set_attribute(attribute:"see_also", value:"https://www-304.ibm.com/support/docview.wss?uid=swg21098628");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"risk_factor", value:"None");

  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/14");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:lotus_sametime");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:sametime");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80, 8088);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

# How to determine the version of a Sametime server:
# https://www-304.ibm.com/support/docview.wss?uid=swg21098628
nsf = "/stcenter.nsf";
buildinfo_path = "/Sametime/buildinfo.txt";
buildinfo_path_75 = "/Sametime/domino/html/sametime/buildinfoST75CF1.txt";


flavor_mapping = 
make_array(
"IMWC",   "Standard", 
"IMWCT",  "Trial",
"IME",    "Entry",
"IMR",    "Connect Server (Resell)",
"IMLU",   "Limited Use");

not_found_msg = "Sametime server install not found on port " + port + ".";
found_no_version_info = 
'  Note : Lotus Sametime install found, but version information\n'+
'         could not be obtained.\n';

info = '\n';

installed = FALSE;

# check for common stcenter.nsf file first, in case the
# admin manages to hide the version info file
res = http_send_recv3(method:"GET", item:nsf, port:port, exit_on_fail:FALSE);

if(res) 
{
  if (egrep(string:res[2], pattern:"stcenter\.nsf/WebCheckProgramSupport"))
    installed = TRUE;
}

page_contents = NULL;

res = http_send_recv3(item:buildinfo_path, port:port, method:"GET", exit_on_fail:FALSE);
if(!isnull(res)) 
{
  if(res[0] =~ "^HTTP\/[0-9]\.[0-9] 200")
    page_contents = res[2];
  else 
  {
    res = http_send_recv3(item:buildinfo_path_75, port:port, method:"GET", exit_on_fail:FALSE);
    if(res[0] =~ "^HTTP\/[0-9]\.[0-9] 200") 
    {
      set_kb_item(name:"www/lotus_sametime/" + port + "/version", value:"7.5 CF1");
      set_kb_item(name:"www/lotus_sametime/" + port + "/version_src", value:"buildinfoST75CF1.txt");
      info += '  Version Source :  buildinfoST75CF1.txt\n';	
      info += '  Version : 7.5 CF1\n';
      page_contents = 'SAMETIME';
    }
  }
}

if(page_contents == NULL && installed == FALSE)
  exit(0, not_found_msg);

if(page_contents == NULL && installed == TRUE)
  info += found_no_version_info;

if(
  ("SAMETIME" >!< page_contents) &&
  (!ereg(pattern:"ST [0-9]", string:page_contents, multiline:TRUE))
)
{
  if(installed == TRUE)
    info += found_no_version_info;
  else exit(0, not_found_msg);
}

set_kb_item(name:"www/lotus_sametime", value:TRUE);
set_kb_item(name:"www/lotus_sametime/" + port + "/installed", value:TRUE);

# SAMETIME7.5.1IMLU_20070627.1101_i5OS_ROCHESTER
# SAMETIME7.5.1CF1_20070717.0801_WIN32AIXSOLLIN_LEXINGTON
# ST 7.0 i5/OS Driver 330
pattern1 = "SAMETIME([^_]+)_([^_]+)_.*";
pattern2 = "ST ([0-9\.]+)";

item = eregmatch(pattern:pattern1, string:page_contents);
if(isnull(item))
  item = eregmatch(pattern:pattern2, string:page_contents);

if(!isnull(item))
{
  if(max_index(item) > 1) # parse version info
  {
    version = item[1];
    version_src = item[0];
    set_kb_item(name:"www/lotus_sametime/" + port + "/version", value:version);
    set_kb_item(name:"www/lotus_sametime/" + port + "/version_src", value:version_src);
    info += '  Version Source : ' + version_src + '\n';	
    info += '  Version : ' + version + '\n';	
  }
  if(max_index(item) > 2) # parse build
  {
    build = item[2];
    set_kb_item(name:"www/lotus_sametime/" + port + "/build", value:build);  
    info += '  Build : ' + build + '\n';
  }

  # try to get platform for info string
  if("WIN32AIXSOL" >< page_contents)
    info += '  Platform : Win32/AIX/Solaris \n';
  if("i5OS" >< page_contents)
    info += '  Platform : IBM i (formerly i5/OS or iSeries)\n';

  item1 = eregmatch(pattern:'Language=([A-Za-z]+)', string:page_contents);
  if(!isnull(item1)) 
  {
    if(max_index(item1) > 1) # language
    {
      language = item1[1];
      set_kb_item(name:"www/lotus_sametime/" + port + "/language", value:language);
      info += '  Language : ' + language + '\n';
    } 
  }

  item1 = eregmatch(pattern:'Flavor=([A-Za-z]+)', string:page_contents);
  if(!isnull(item1))
  {
    if(max_index(item1) > 1) # flavor
    {
      flavor = item1[1];
      set_kb_item(name:"www/lotus_sametime/" + port + "/flavor", value:flavor);
      flavor_ui = NULL;
      flavor_ui = flavor_mapping[flavor];
      if(isnull(flavor_ui))
        flavor_ui = flavor;
      info += '  Flavor : ' + flavor_ui + '\n' +
      '  (Note: Flavor shown above may be incorrect if the server\n'+
      '  has been upgraded from Trial/Entry/Connect/Limited Use to\n' +
      '  Standard.)\n';
    }
  }
  item1 = eregmatch(pattern:'Type=([A-Za-z]+)', string:page_contents);
  if(!isnull(item1))
  {
    if(max_index(item1) > 1) # type
    {
      type = item1[1];
      set_kb_item(name:"www/lotus_sametime/" + port + "/type", value:type);
      info += '  Type: ' + type + '\n';    
    }
  }
}

if (report_verbosity > 0) 
  security_note(port:port, extra:info);
else security_note(port);
