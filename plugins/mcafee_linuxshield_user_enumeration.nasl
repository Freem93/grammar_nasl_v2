#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(44986);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/27 15:03:55 $");

  script_name(english:"McAfee LinuxShield Login Username Enumeration");
  script_summary(english:"Attempts to login with valid/invalid accounts");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application that leaks information."
  );
  script_set_attribute(attribute:"description", value:
"McAfee LinuxShield is installed on the remote host.  

The installed version of this software fails to respond with
consistent error messages when a user attempts to login with existing
and non-existing accounts. 

A remote, unauthenticated attacker may exploit this vulnerability to
enumerate valid users for the remote web application."
  );
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2010/Mar/28" );
  script_set_attribute(attribute:"solution", value:"Unknown at this time.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
  script_set_attribute(attribute:"vuln_publication_date",  value:"2010/03/03");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/03/04");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/03/02");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:mcafee:linuxshield");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/apache");
  script_require_ports("Services/www", 55443);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("url_func.inc");

port = get_http_port(default:55443);

res = http_get_cache(port:port, item:"/", exit_on_fail:1); 

if('"McAfee LinuxShield"' >!< res && "This browser is not supported by LinuxShield" >!< res)
  exit(0,"The web server on port "+port+" does not appear to be hosting McAfee LinuxShield.");

url = strstr(res, "<form id=loginForm method=POST onSubmit='return checkForm();' action=") - 
      '<form id=loginForm method=POST onSubmit=\'return checkForm();\' action="';
url = url - strstr(url,'">');

if(url !~ "^/[0-9A-Za-z_-]+/nails$") 
  exit(1,"Could not determine McAfee LinuxShield login url on port "+ port + ".");

users = make_list("nails", # Valid account
                  "nessus-"+ unixtime());  # Bogus account

user_existent = NULL;
user_nonexistent = NULL;

errors = make_array();
passwd = rand();

foreach user (users)
{
  data = 'pg=login&tplt=mainframe.html&user=' + user + '&password='+ passwd;

   res = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    content_type: "application/x-www-form-urlencoded",
    data:data,
    exit_on_fail:1 
  );

  # We should see an error....   
  if(
    res[2] &&
    "<TITLE>LinuxShield Error</TITLE>" >< res[2] && 
    '<td class=recordRow><b>34</b></td>' >< res[2]
  )
    # Strip out new lines, so that we can use it later in our regex to avoid potential FP's.  
    r = str_replace(find:'\n',replace:"",string:res[2]); 
  else
   exit(1, "Failed to receive desired response for login request on port "+ port + "."); 

  # Look for error code 34 and description ...  

  if (isnull(user_existent) && 
      ereg(pattern:"<td class=recordRow><b>34</b></td>\s*\t*<td class=recordRow><span id=desc>authentication failure</span>&nbsp;</td>",string:r))
  {
    user_existent = user;
    errors[user] = "authentication failure";
  }
  else if (isnull(user_nonexistent) &&
      ereg(pattern:"<td class=recordRow><b>34</b></td>\s*\t*<td class=recordRow><span id=desc></span>&nbsp;</td>",string:r))
  {
    user_nonexistent = user;
    errors[user] = "none";
    # i.e in this case error desc is missing.
  }

  if (user_existent && user_nonexistent)
  {
    if (report_verbosity > 0)
    {
      report = '\n' +
        'Nessus was able to verify the issue by attempting to login with the\n' +
        'following users :\n' + 
        '\n' +
        '  Existing User  : ' + user_existent + '\n' +
        '  Response Error : ' + errors[user_existent] + '\n' +
        '\n' +
        '  Invalid User   : ' + user_nonexistent + '\n' +
        '  Response Error : ' + errors[user_nonexistent] + '\n' ;
      security_warning(port:port, extra:report);
    }
    else security_warning(port);
    exit(0); 
  }
}  
exit(0, "The McAfee LinuxShield at "+build_url(port:port, qs:'/')+" is not affected.");
