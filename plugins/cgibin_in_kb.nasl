#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if(description)
{
 script_id(10308);
 script_version ("$Revision: 1.8 $");
 script_cvs_date("$Date: 2011/03/17 18:46:05 $");

 script_name(english:"Nessus Internal: Put cgibin() in the KB");
 script_summary(english:"cgibin() in kb");
 
 script_set_attribute(
   attribute:"synopsis",
   value:"This plugin performs an internal Nessus function."
 );
 script_set_attribute( attribute:"description",  value:
"This plugin puts the content of cgibin() in the KB so that the
function cgi_dirs() can work properly." );
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_attribute(attribute:"risk_factor", value:"None");
 script_set_attribute(attribute:"plugin_publication_date", value: "2003/02/28");
 script_set_attribute(attribute:"plugin_type", value:"settings");
 script_end_attributes();

 script_category(ACT_SETTINGS);
 script_family(english:"Settings");
 
 script_copyright(english:"This script is Copyright (C) 2003-2011 Tenable Network Security, Inc.");
 
 exit(0);
}



dir = cgibin();
cgis = split(dir, sep:":", keep:FALSE);
foreach dir (cgis)
{
 set_kb_item(name:"/tmp/cgibin", value:dir);
}
exit(0);
