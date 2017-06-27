#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(42057);
 script_version("$Revision: 1.8 $");
 script_cvs_date("$Date: 2016/06/16 22:16:21 $");

 script_name(english: "Web Server Allows Password Auto-Completion");
 script_summary(english: "Uses the results of webmirror.nasl.");
 
 script_set_attribute(attribute:"synopsis", value:
"The 'autocomplete' attribute is not disabled on password fields.");
 script_set_attribute(attribute:"description", value:
"The remote web server contains at least one HTML form field that has
an input of type 'password' where 'autocomplete' is not set to 'off'.

While this does not represent a risk to this web server per se, it
does mean that users who use the affected forms may have their
credentials saved in their browsers, which could in turn lead to a
loss of confidentiality if any of them use a shared host or if their
machine is compromised at some point.");
 script_set_attribute(attribute:"solution", value:
"Add the attribute 'autocomplete=off' to these fields to prevent
browsers from caching credentials.");
 script_set_attribute(attribute:"risk_factor", value:"None" );

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/10/07");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_family(english: "Web Servers");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www",80);
 exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");

port = get_http_port(default:80);

kb = get_kb_item_or_exit("www/" + port + "/AutoCompletePasswordForms");

e = "";
foreach line (split(kb, keep: 0))
  e += split_long_line(line: line) + '\n';
security_note(port:port, extra: e);

