# ----------------------------------------------------
# (c) Recx Ltd 2009-2012
# http://www.recx.co.uk/
#
# Oracle Application Express Detection on HTTP ports
# Version 1.1
# ----------------------------------------------------

include("compat.inc");

if (description)
{
  script_id(64704);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2013/02/22 19:46:31 $");

  script_name(english:"Oracle Application Express (Apex) Detection");
  script_summary(english:"Checks the web server for the presence of Oracle Application Express.");

  script_set_attribute(attribute:"synopsis", value:"The remote host is running Oracle Apex.");
  script_set_attribute(attribute:"description", value:"The remote host is running Oracle Application Express (Apex).");
  script_set_attribute(attribute:"solution", value:"n/a");
  script_set_attribute(attribute:"see_also", value:"http://www.oracle.com/technetwork/developer-tools/apex/index.html");
  script_set_attribute(attribute:"risk_factor", value:"None");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/20");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:oracle:application_express");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");

  script_copyright(english:"This script is Copyright (C) 2009-2013 Recx Ltd.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080, 80, 443);

  exit(0);
}

include("global_settings.inc");
include("http_func.inc");
include("http_keepalive.inc");

function raise_finding(port, info, response)
{
  local_var report, location;
  if(report_verbosity > 0)
  {
    location = build_url(port:port, qs:info);
    report = '\nAn Oracle Application Express (Apex) instance was detected :\n' +
             '\n  URL : ' + location + '\n';
    if(report_verbosity > 1)
      report += '\nResponse : \n\n' + response + '\n';
    security_note(port:port, extra:report);
  }
  else security_note(port);
}

port = get_http_port(default:8080);

if (!get_port_state(port)) exit(0, "Port " + port + " is not open.");

url = make_array();
pattern = make_array();

# Define Oracle Apex specific request URLs that trigger known responses.
url[0] = "/apex/f?p=nessuscheck";
url[1] = "/pls/apex/f?p=nessuscheck";

# Define Oracle Apex version specific patterns.
pattern[0] = "Could not determine workspace";                             #  Apex 3.2 to 4.0
pattern[1] = 'Alias "nessuscheck" does not exist';                        #  Apex 4.1 and 4.1.1
pattern[2] = 'Application with the alias "nessuscheck" does not exist';   #  Apex 4.2

flag = 0;

# Iterate through common Oracle Apex paths in order to trigger known responses.
for(i=0;url[i];i=i+1)
{
  request = http_get(item:url[i], port:port);
  buffer = http_keepalive_send_recv(port:port, data:request);
  if (buffer == NULL)
    exit(1, "Unable to establish connection to server on port " + port + ".");

  # Search buffer for output consistent with the presence of Oracle Apex instances
  for(j=0;pattern[j];j=j+1)
  {
    if (pattern[j] >< buffer)
    {
      flag = 1;
      # Remove the nessuscheck part of URL
      ApexURL = url[i] - "f?p=nessuscheck";

      # Create finding
      raise_finding(port:port,info:ApexURL,response:pattern[j]);

      # Define patterns which allow the determination of the Apex IMAGE_PREFIX.
      # <img src="/i/error.gif" border="0" />   - Apex 3.2, 3.2.1, 4.0, 4.0.1, 4.0.2, 4.1.0, 4.1.1, 4.2.0
      ipMatch = eregmatch(pattern: '<img src="/(.*)/error.gif" border="0" />', string: buffer);
      if (isnull(ipMatch[1]))
        ApexImgPrefix = "i";
      else
	ApexImgPrefix = ipMatch[1];

      # Set Knowledge Base items for Apex
      set_kb_item(name:"Oracle/Apex/"+port, value:"TRUE"); # Apex on this port
      set_kb_item(name:"Oracle/Apex", value:"TRUE"); # Apex on this host
      set_kb_item(name:"Oracle/Apex/"+port+"/Location", value:ApexURL);
      set_kb_item(name:"Oracle/Apex/"+port+"/ImagePrefix", value:ApexImgPrefix);

      # Exit the for loop to prevent unecessary requests
      if(flag) break;
    }
  } # Iterate onto next pattern
  # Exit the for loop to prevent unecessary requests, if the flag is set.
  if(flag) break;
} # Iterate onto next ApexURL

if(!flag)
  exit(0, "Oracle Apex does not appear to be listening on port " + port + ".");
exit(0);
