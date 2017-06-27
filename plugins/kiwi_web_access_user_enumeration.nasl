#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(43154);
  script_version("$Revision: 1.6 $");

  script_bugtraq_id(37282);
  script_osvdb_id(60881);
  script_xref(name:"Secunia", value:"37465");

  script_name(english:"Kiwi Syslog Server Web Access Login Username Enumeration");
  script_summary(english:"Attempts to login with valid/invalid accounts");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application that leaks information."
  );
  script_set_attribute(attribute:"description", value:
"Kiwi Syslog Web Access is installed on the remote host.  The
installed version responds with different error messages when an user
attempts to login with existent and non-existent accounts.  A remote
unauthenticated attacker may exploit this vulnerability to enumerate
valid users for the remote web application. 

The installed version is reportedly also affected by a vulnerability
that may allow an attacker to read arbitrary local files by
registering a new application, although Nessus has not tested for it."
  );
  script_set_attribute(attribute:"solution", value:"Unknown at this time");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/12/10"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/12/14"
  );
 script_cvs_date("$Date: 2015/09/24 21:17:11 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_ports("Services/www", 8088);
  script_require_keys("www/ASP");
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:8088);

if (!can_host_asp(port:port)) exit(0, "The web server on port" + port + " does not support ASP scripts.");

url = "/gateway.aspx";
res = http_send_recv3(method:"GET",item:url,port:port);
if (isnull(res)) exit(1, "The web server on port "+ port + " failed to respond.");

if("Login Gateway - Kiwi Syslog Web Access" >!< res[2]) 
  exit(0,"The web server on port "+port+" does not appear to be hosting Kiwi Syslog Web Access.");

state = NULL;
if(egrep(pattern:'__VIEWSTATE" value=".+" />',string:res[2]))
{
  state = strstr(res[2], 'id="__VIEWSTATE" value=') - 'id="__VIEWSTATE" value="';
  state = state - strstr(state, '" />');
}

if(isnull(state)) exit(1, "Could not extract __VIEWSTATE information from "+build_url(port:port, qs:url)+".");
state = urlencode(str:state);

validation = NULL;
if(egrep(pattern:'__EVENTVALIDATION" value=".+" />',string:res[2]))
{
  validation  = strstr(res[2], 'id="__EVENTVALIDATION" value="') - 'id="__EVENTVALIDATION" value="';
  validation  = validation - strstr(validation, '" />');
}

if(isnull(validation)) exit(1, " Could not extract __EVENTVALIDATION information from "+build_url(port:port, qs:url)+".");
validation = urlencode(str:validation);

users = make_list("Administrator", # Valid account
                  "nessus-"+ unixtime());  # Bogus account

user_existent = NULL;
user_nonexistent = NULL;

errors = make_array();
passwd = rand();

foreach user (users)
{
  data = '__EVENTTARGET=&"+
         "__EVENTARGUMENT=&' +
         '__VIEWSTATE='         + state  + "&"+
         '__EVENTVALIDATION='   + validation + "&"+
         'KiwiLogin$UserName='  + user + "&"+
         'KiwiLogin$Password='  + passwd + "&"+
         'KiwiLogin$LoginButton=Log In';

  # Send a login POST request.
  res = http_send_recv3(
    method:"POST", 
    item:url, 
    port:port,
    add_headers: make_array("Content-Type", "application/x-www-form-urlencoded",
    "Content-Length",strlen(data)),
    data:data
  );
  if (isnull(res)) exit(1, "The web server on port "+ port + " failed to respond.");

  if (isnull(user_existent) && "52: Authentication Failed.  Incorrect password." >< res[2] )
  {
    user_existent = user;
    error = strstr(res[2],'52: Authentication Failed.  Incorrect password.');
    errors[user] = error - strstr(error, "\n\n', 'KiwiLogin_Password");
  }
  else if (isnull(user_nonexistent) && '51: Authentication Failed.  Unknown user name.' >< res[2] )
  {
    user_nonexistent = user;
    error = strstr(res[2],'51: Authentication Failed.  Unknown user name.');
    errors[user] = error - strstr(error, "\n\n', 'KiwiLogin_UserName") ;
  }

  if (user_existent && user_nonexistent)
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        "Nessus was able to verify the issue by attempting to login with " + '\n' +
        "following users :" + '\n' + 
        '\n' +
        "  Existing User  : " + user_existent + '\n' +
        "  Response Error : " + errors[user_existent] + '\n' +
        '\n' +
        "  Invalid User   : " + user_nonexistent + '\n' +
        "  Response Error : " + errors[user_nonexistent] + '\n' ;
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0); 
  }
}  
exit(0, "The Kiwi Syslog Web Access installation at "+build_url(port:port, qs:url)+" is not affected.");
