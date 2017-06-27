#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) 
{
  script_id(25082);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2013/08/26 22:30:53 $");

  script_cve_id("CVE-2007-1681");
  script_bugtraq_id(23539);
  script_osvdb_id(34902);

  script_name(english:"Sun Java Web Console LibWebconsole_Services.SO Remote Format String");
  script_summary(english:"Checks Sun Java Web Console Version");
 
  script_set_attribute(attribute:"synopsis", value:
"The remote web server is prone to a format string attack." );
  script_set_attribute(attribute:"description", value:
"The remote host is running SUN Java Web Console. 

The remote version of this service does not properly sanitize calls
to the syslog function. By sending a specially crafted request
it is possible to exploit this format string error.
An attacker can exploit it to execute code with the privileges of
the web server." );
  script_set_attribute(attribute:"see_also", value:"http://www.nruns.com/security_advisory_sun_java_format_string.php");
  # http://web.archive.org/web/20070504053040/http://sunsolve.sun.com/search/document.do?assetkey=1-26-102854-1
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?49b94d2d");
  script_set_attribute(attribute:"solution", value:
"See the vendor's update for information on workarounds and solutions
to this issue.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"patch_publication_date", value:"2007/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/04/23");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value: "cpe:/a:sun:java_web_console");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
  script_dependencie("http_version.nasl", "ssh_detect.nasl");
  script_require_ports("Services/www", 6789);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if (!get_kb_item('Settings/PCI_DSS'))
{
 ssh_port = get_kb_item("Services/ssh");
 if (!ssh_port) exit(0);

 banner = get_kb_item(string("SSH/banner/", ssh_port));
 if ("Sun_SSH" >!< banner) exit(0,"The remote SSH banner on port "+ssh_port+" is not from a Solaris system."); 
}


port = 6789;
if (!get_port_state(port))
  exit(1, "Port "+port+" is not open.");

w = http_send_recv3(method:"GET", item:"/console/html/en/console_version.shtml", port:port,exit_on_fail:TRUE);

if ("<title>Sun Java(TM) Web Console: Version</title>" >!< w[2])
  exit (0,"The remote web server on port "+ port + " does not appear to be Sun Java(TM) Web Console.");

w = http_send_recv3(port: port, item:"/console/html/en/version.txt", method:"GET",exit_on_fail:TRUE);

#res = strcat(w[0], w[1], '\r\n', w[2]);

if (!egrep(pattern:"^[0-9]+\.[0-9]+\.[0-9]+$", string:w[2]))
  exit (1,"Failed to extract version in desired format from Sun Java(TM) Web Console listening on port "+ port+".");

vers = ereg_replace(pattern:"^([0-9]+\.[0-9]+\.[0-9]+)$", string:w[2], replace:"\1");
vers = split(vers, sep:".", keep:FALSE);

if ( (int(vers[0])   < 2) ||
     ((int(vers[0]) == 2) && (int(vers[1]) < 2)) ||
     ((int(vers[0]) == 2) && (int(vers[1]) == 2) && (int(vers[2]) < 6)) )
{
 # don't worry about checking for the 2.2.4 patch in a PCI scan
 if (get_kb_item('Settings/PCI_DSS'))
 {
   if(report_verbosity > 0)
   {
     report = '\n'+
              'Sun Java(TM) Web Console version '+ join(vers,sep:".") + '\n' +
              'is installed on the remote host. Nessus did not attempt to\n' +
              'determine if patches 121211-02 or 121212-02 have been applied.\n';
     security_hole(port:port,extra:report);
   }
   else
     security_hole(port);
   exit(0);
 }

 # patched in 2.2.6 except for solaris 10 ( patched in 2.2.4 )
 w = http_send_recv3(method:"GET", item:"/console/html/en/versionDate.txt", port:port,exit_on_fail:TRUE);

 #res = strcat(w[0], w[1], '\r\n', w[2]);

 if (!egrep(pattern:"^[0-9]+/[0-9]+/[0-9]+$", string:w[2]))
   exit (1,"Failed to extract version date in desired format from Sun Java(TM) Web Console listening on port "+ port+".");
 
 date = ereg_replace(pattern:"^([0-9]+/[0-9]+/[0-9]+)$", string:w[2], replace:"\1");
 date = split(date, sep:"/", keep:FALSE);

 if ( int(date[0])   < 2007 ||
      (int(date[0]) == 2007 && int(date[1]) < 3) )
 {  
   if(report_verbosity > 0)
   {
     report = '\n'+
              'Sun Java(TM) Web Console version '+ join(vers,sep:".") + ' ('+join(date,sep:"/")+ ')\n'+
              'is installed on the remote host.\n';
     security_hole(port:port,extra:report);
   }
   else
     security_hole(port); 
   exit(0);
 }
 else
  exit(0,"Sun Java(TM) Web Console version date '"+ join(date,sep:"/")+"' is newer than 2007/3 and hence not affected.");
}
else
  exit(0,"Sun Java(TM) Web Console version '"+join(vers,sep:".")+"' is installed on port "+ port + " and hence not affected.");
