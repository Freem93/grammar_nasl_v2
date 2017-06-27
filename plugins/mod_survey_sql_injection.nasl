#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(11609);
 script_version("$Revision: 1.15 $");
 script_bugtraq_id(7192);
 script_osvdb_id(4568);
 script_xref(name:"Secunia", value:"11196");

 script_name(english:"mod_survey For Apache ENV Tags SQL Injection");
 script_summary(english:"mod_survey SQL injection");

 script_set_attribute( attribute:"synopsis", value:
"The web server module on the remote host has a SQL injection
vulnerability." );
 script_set_attribute( attribute:"description",  value:
"According to the banner, the remote host is using a vulnerable
version of mod_survey, a Perl module for managing online surveys.
This version has a flaw that could result in a SQL injection attack
when the module is being used with a database backend.  A remote
attacker could exploit this to take control of the database." );
 script_set_attribute(
   attribute:"solution", 
   value:"Upgrade to mod_survey 3.0.14e / 3.0.15pre6 or later."
 );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/05/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2003/03/28");
 script_cvs_date("$Date: 2011/03/12 01:05:16 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Web Servers");

 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");

 script_dependencie("http_version.nasl", "find_service1.nasl", "httpver.nasl", "no404.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 exit(0);
}

#
# The script code starts here
#


include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
 
port = get_http_port(default:80);
files = get_kb_list(string("www/",port, "/content/extensions/survey"));
if (isnull(files)) exit(0);

files = make_list(files);
res = http_send_recv3(method:"GET", item:files[0], port:port);
if (isnull(res)) exit(0);

res = res[0] + res[1] + res[2];

if ("Mod_Survey" >< res)
{
  if (egrep(pattern:"Mod_Survey v([0-2]\.|3\.0\.([0-9][^0-9]|1[0-3]|14[^a-z]|14[a-d]|15pre[0-5]))", string:res))
  {
    security_hole(port);
    set_kb_item(name: 'www/'+port+'/SQLInjection', value: TRUE);
    exit(0);
  }
}
