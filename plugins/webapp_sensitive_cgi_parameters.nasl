#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
 script_id(40773);
 script_version("$Revision: 1.10 $");
 script_cvs_date("$Date: 2012/08/17 18:47:00 $");

 script_name(english:"Web Application Potentially Sensitive CGI Parameter Detection");
 script_summary(english: "Common sensitive CGI parameters names");

 script_set_attribute(attribute:"synopsis", value:
"An application was found that may use CGI parameters to control
sensitive information.");

 script_set_attribute(attribute:"description", value:
"According to their names, some CGI parameters may control sensitive
data (e.g., ID, privileges, commands, prices, credit card data, etc.). 
In the course of using an application, these variables may disclose
sensitive data or be prone to tampering that could result in privilege
escalation.  These parameters should be examined to determine what
type of data is controlled and if it poses a security risk.

** This plugin only reports information that may be useful for auditors
** or pen-testers, not a real flaw.");

 script_set_attribute(attribute:"solution", value: 
"Ensure sensitive data is not disclosed by CGI parameters.  In
addition, do not use CGI parameters to control access to resources or
privileges.");

 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2009/08/25");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2009-2012 Tenable Network Security, Inc.");
 script_family(english: "CGI abuses");

 script_dependencie("http_version.nasl", "webmirror.nasl");
 script_require_ports("Services/www", 80);
 script_require_keys("Settings/enable_web_app_tests");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("torture_cgi_func.inc");

port = torture_cgi_init();

names = make_array(
"cmd",		"Possibly a command - try 'edit', 'view', 'delete'...",
"command",	"Possibly a command - try 'edit', 'view', 'delete'...",
"id",		"Potential horizontal or vertical privilege escalation",
"price",	"Manipulating this could allow for price modification",
"admin",	"Potential vertical privilege escalation - try '1', 'yes'...",
"role",		"Potential privilege escalation - try 'admin', 'super'...",
"pwd",		"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"pass",		"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"passwd",	"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"password",	"Possibly a clear or hashed password, vulnerable to sniffing or dictionary attack",
"user",		"Potential horizontal privilege escalation - try another user ID",
"userid",	"Potential horizontal or vertical privilege escalation",
"usr",		"Potential horizontal privilege escalation - try another user ID",
"cc",		"Possibly credit card data - please examine it",
"expd",		"Possibly credit card expiration date",
"cvv",		"Possibly a credit card cryptogram" );


t = get_port_transport(port);

cgis = get_cgi_list(port: port);

rep = "";
foreach cgi (cgis)
{
  repcgi = "";
  args_l = get_cgi_arg_list(port: port, cgi: cgi);
  args_l = replace_cgi_args_token(port: port, args_list: args_l, max_tokens: 1);
  foreach arg (args_l)
  {
    name = tolower(arg);
    foreach k (keys(names))
      if (k == name)
      {
	a = names[k];
	if (t > ENCAPS_IP)
          a = str_replace( string: a,
	      		   find: "vulnerable to sniffing or ",
			   replace: "vulnerable to ");
        repcgi = strcat(repcgi, arg, ' : ', a, '\n');
	break;
      }
  }
  if (strlen(repcgi) > 0)
  rep = strcat(rep, 'Potentially sensitive parameters for CGI ', cgi, ' :\n\n', repcgi, '\n');
}

if (strlen(rep) > 0)
{
  security_note(port: port, extra: '\n'+rep);
  if (COMMAND_LINE) display(rep);
}
