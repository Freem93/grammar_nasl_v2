#
# (C) Tenable Network Security, Inc.
#
#  @DEPRECATED@
#
#  Disabled on 2016/06/13.
#  Confirmed not required for PCI-DSS ASV requirements.
#

include("compat.inc");

if (description)
{
 script_id(56306);
 script_version("$Revision: 1.4 $");
 script_cvs_date("$Date: 2016/06/16 22:16:21 $");

 script_name(english:"Web Server Allows Password Auto-Completion (PCI-DSS variant) (deprecated)");
 script_summary(english:"Uses the results of webmirror.nasl.");
 
 script_set_attribute(attribute:"synopsis", value:
"This plugin has been deprecated.");
 script_set_attribute(attribute:"description", value:
"This plugin has been deprecated because the corresponding failure item
in the ASV Program Guide no longer pertains, as of the May 2013
release. Plugin ID 42057 should be used instead.");
 script_set_attribute(attribute:"solution", value:"n/a");
 script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/27");

 script_set_attribute(attribute:"plugin_type", value: "remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO); 
 script_family(english: "Web Servers");

 script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");

 script_dependencie("webmirror.nasl");
 script_require_ports("Services/www", 80);

 exit(0);
}

exit(0,"This plugin has been deprecated. Use www_autocomplete_passwords.nasl (plugin ID 42057) instead.");

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");

if (!get_kb_item("Settings/PCI_DSS")) exit(0, "PCI-DSS compliance checking is not enabled.");

port = get_http_port(default:80, embedded:TRUE);

kb = get_kb_item_or_exit("www/"+port+"/AutoCompletePasswordForms");

e = "";
foreach line (split(kb, keep: 0))
  e += split_long_line(line: line) + '\n';
security_warning(port:port, extra:e);
