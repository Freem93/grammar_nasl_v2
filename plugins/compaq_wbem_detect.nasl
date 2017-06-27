#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10746);
 script_version("$Revision: 1.30 $");
 script_cvs_date("$Date: 2016/05/19 20:49:08 $");

 script_name(english:"HP System Management Homepage Detection");
 script_summary(english:"Checks for HP System Management Homepage.");

 script_set_attribute(attribute:"synopsis", value:
"A management service is running on the remote web server.");
 script_set_attribute(attribute:"description", value:
"HP System Management Homepage (SMH), formerly Compaq Web Management,
is running on the remote web server. SMH is a web-based application
for managing HP ProLiant and Integrity servers, or HP 9000 and HP
Integrity servers.");
 # http://www8.hp.com/us/en/products/server-software/product-detail.html?oid=344313#!tab%3Dfeatures
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5ce81e8f");
 script_set_attribute(attribute:"solution", value:
"It is suggested that access to this service be restricted.");
 script_set_attribute(attribute:"risk_factor", value:"None");

 script_set_attribute(attribute:"plugin_publication_date", value:"2001/08/29");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:hp:system_management_homepage");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
 script_family(english:"Web Servers");

 script_dependencie("find_service1.nasl", "httpver.nasl");
 script_require_ports("Services/www", 2301, 2381);

 exit(0);
}

#
# The script code starts here
#

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("http.inc");
include("webapp_func.inc");

installs = NULL;

ports = add_port_in_list(list:get_kb_list("Services/www"), port:2301);
ports = add_port_in_list(list:ports, port:2381);

report_fired = FALSE;

foreach port (ports)
{
  install_detected = FALSE;
  banner = get_http_banner(port:port);
  if (!banner || "Server: CompaqHTTPServer/" >!< banner) continue;
  prod = NULL;
  source_line = NULL;
  version = NULL;

  foreach line (split(banner, keep:FALSE))
  {
    match = eregmatch(pattern:"^Server: CompaqHTTPServer/(.*)", string:line);
    if (!isnull(match))
    {
      source_line = line;
      tmp = match[1];
      if ("HP System Management Homepage" >< tmp)
      {
        prod = "HP System Management Homepage";
        tmp = strstr(tmp, prod) - (prod + "/");
        if ("/" >< tmp) version = strstr(tmp, "/") - "/";
        if (" httpd" >< tmp) version = tmp - strstr(tmp, " httpd");
      }
      if ("HPE System Management Homepage" >< tmp)
      {
        prod = "HPE System Management Homepage";
        tmp = strstr(tmp, prod) - prod;
        if ("/" >< tmp) version = strstr(tmp, "/") - "/";
        if (" httpd" >< tmp) version = tmp - strstr(tmp, " httpd");
      }
      break;
    }
  }

  if (isnull(version) &&
      ("HP System Management Homepage" >< prod ||
       "HPE System Management Homepage" >< prod)
     )
  {
    res = http_send_recv3(
      method          : "GET",
      port            : port,
      item            : '/',
      follow_redirect : 3
    );
    if (isnull(res))
    {
      comment += "The web server listening on port "+port+' failed to respond to a request for the login page.\n';
      continue;
    }
    # Unless we're paranoid, ignore the install if it just serves to redirect to another port.
    if (
      report_paranoia < 2 &&
      'Unable to complete your request due to added security features' >< res[2] &&
      'allowing access to the web-enabled interface using the secure HTTPS protocol' >< res[2]
    )
    {
      comment += "HP System Management Homepage is listening on port "+port+', but since it redirects to an HTTPS port and is not otherwise usable, it is ignored.\n';
      continue;
    }
    if (
      'description" content="System Management Homepage"' >< res[2] ||
      'smhversion = "HP System Management Homepage' >< res[2] ||
      'smhversion = "HPE System Management Homepage' >< res[2] ||
      'smhproductname = "HP System Management Homepage' >< res[2] ||
      'smhproductname = "HPE System Management Homepage' >< res[2] ||
      '<td>System Management Homepage requires Javascript' >< res[2]
    )
    {
      pat = 'smhversion = "[HPE]{2,3} System Management Homepage v([0-9._]+)"';
      foreach line (split(res[2], keep:FALSE))
      {
        line = chomp(line);
        match = eregmatch(pattern:pat, string:line);
        if (!isnull(match))
        {
          source_line = line;
          version = match[1];
          break;
        }
      }
    }
    else
    {
      comment += "The response from port "+port+" does not look like HP System Management Homepage.";
      continue;
    }
    install_detected = TRUE;
  }
  else if(!isnull(version) &&
          ("HP System Management Homepage" >< prod ||
           "HPE System Management Homepage" >< prod )
          )
  {
    install_detected = TRUE;
  }

  if(install_detected)
  {
    installs = add_install(
      installs : NULL,    # nb: there aren't any previous installs.
      dir      : '',
      ver      : version,
      appname  : 'hp_smh',
      port     : port
    );
    set_kb_item(name:"www/"+port+"/hp_smh/variant", value:prod);
    if (source_line) set_kb_item(name:"www/"+port+"/hp_smh/source", value:source_line);
    set_kb_item(name:"Services/www/"+port+"/embedded", value:TRUE);
    set_kb_item(name:"Services/www/hp_smh", value:port);
  }

  if (!isnull(installs))
  {
    report_fired = TRUE;
    if (report_verbosity > 0)
    {
      if (isnull(version)) version = UNKNOWN_VER;

      report = '\n' + 'The following instance of ' + prod + ' was detected on the remote host :' +
               '\n' +
               '\n' + '  URL     : ' + build_url(qs:'', port:port) +
               '\n' + '  Source  : ' + source_line +
               '\n' + '  Version : ' + version +
               '\n';
      security_note(port:port, extra:report);
    }
    else security_note(port);
  }
}

if (!report_fired)
{
  if (comment) exit(1, chomp(comment));
  else exit(0, "No installations of HP System Management Homepage / Compaq Web Management were found.");
}
