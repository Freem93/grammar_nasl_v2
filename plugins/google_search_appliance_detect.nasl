#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if(description)
{
   script_id(20228);
   script_version ("$Revision: 1.12 $");
   
   script_name(english:"Google Search Appliance Detection");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote host is a Google Search Appliance." );
 script_set_attribute(attribute:"description", value:
"The remote host seems to be a Google Search Appliance. These 
appliances are used to index the files contained on an intranet and 
make them searchable.

Make sure that this appliance can only be accessed by authorized 
personel or that the data it indexes is public." );
 script_set_attribute(attribute:"solution", value:
"Restrict the set of hosts to index in the appliance, if necessary." );
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/11/20");
 script_cvs_date("$Date: 2012/08/06 16:33:44 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_set_attribute(attribute:"cpe",value:"cpe:/h:google:search_appliance");
script_end_attributes();

   summary["english"] = "Detects a Google Appliance";
   script_summary(english:summary["english"]);
 
   script_category(ACT_GATHER_INFO);
 
   script_copyright(english: "This script is Copyright (C) 2005-2012 Tenable Network Security, Inc.");
   script_family(english: "Web Servers");
   script_dependencie("http_version.nasl");
   script_require_ports("Services/www", 80);
   exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:80);

res = http_get_cache(item:"/", port:port, exit_on_fail: 1);
if ( ereg(pattern:"^HTTP.* 302 ", string:res) )
{
 if ( egrep(pattern:"^Location: /search\?site=.*&client=.*&output=.*&proxystylesheet=.*&proxycustom=.*", string:res) )
 {

        set_kb_item(
          name:string("www/", port, "/google_search_appliance"),
          value:TRUE
        );
	security_note(port);
 }
}
