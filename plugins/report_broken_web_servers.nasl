#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(42799);
 script_version("$Revision: 1.5 $");
 script_cvs_date("$Date: 2011/08/17 16:19:40 $");

 script_name(english: "Broken Web Servers");
 script_summary(english: "Report broken web servers");

 script_set_attribute(attribute:"synopsis", value:
"Tests on this web server have been disabled.");
 script_set_attribute(attribute:"description", value:
"The remote web server seems password protected or misconfigured.  
Further tests on it were disabled so that the whole scan is not 
slowed down." );
 script_set_attribute(attribute:"solution", value: "n/a");
 script_set_attribute(attribute:"risk_factor", value: "None");
 script_set_attribute(attribute:"plugin_publication_date", value:"2009/11/13");
 script_set_attribute(attribute:"plugin_type", value:"summary");
 script_end_attributes();

 script_category(ACT_END);
 script_copyright(english:"This script is Copyright (C) 2009-2011 Tenable Network Security, Inc.");
 script_family(english: "Web Servers");
 script_dependencies("httpver.nasl", "broken_web_server.nasl");
 script_require_ports("Services/www");
 exit(0);
}

#
include("global_settings.inc");

if ( report_verbosity < 2 ) exit(0, "report_verbosity is too low");

port = get_kb_item("Services/www");
if (!port) exit(0);

if (! get_kb_item("Services/www/" +port+ "/broken")) exit(0);

l = get_kb_list("Services/www/"+port+"/declared_broken_by");
who = "";
foreach w (l)
  who = strcat(who, ' ', w, '\n');
l = get_kb_list("Services/www/" +port+ "/broken/reason");
why = "";
nw = 0;
foreach w (l)
  if (w != 'unknown')
  {
    why = strcat(why, ' ', w, '\n');
    nw ++;
  }

report = '';
if (who)
  report = strcat('by :\n', who);

if (why) 
{
  report += 'for the following reason';
  if (nw > 1) report += 's';
  report = strcat(report, ' :\n', why);
}

if (report)
{
  report = strcat('\nThis web server was declared broken ', report, '\n');
  security_note(port: port, extra: report);
  if (COMMAND_LINE) display(report);
}
else
  security_note(port);
