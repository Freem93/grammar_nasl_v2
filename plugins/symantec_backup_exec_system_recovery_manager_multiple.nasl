#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description) {
  script_id(30211);
  script_version("$Revision: 1.14 $");

  script_cve_id("CVE-2008-0457");
  script_bugtraq_id(27487);
  script_osvdb_id(41149);

  script_name(english:"Symantec Backup Exec System Recovery Manager FileUpload Class Unauthorized File Upload");
  script_summary(english:"Checks for reportsfile parameter directory traversal vulnerability in Symantec BESRM 7");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote web server contains a Tomcat servlet that fails to validate
user input." );
 script_set_attribute(attribute:"description", value:
"The remote host appears to be running Symantec Backup Exec System
Recovery Manager, a backup manager solution. 

The version of Recovery Manager on the remote host includes the Tomcat
Servlet 'FileUpload' that fails to validate the user input.  An
unauthenticated attacker may be able to exploit this issue to upload a
jsp script to execute code on the remote host with SYSTEM privileges." );
 script_set_attribute(attribute:"see_also", value:"http://www.symantec.com/avcenter/security/Content/2008.02.04.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrade to version 7.0.3 or later." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");
 script_cwe_id(20);
 script_set_attribute(attribute:"plugin_publication_date", value: "2008/02/09");
 script_set_attribute(attribute:"patch_publication_date", value: "2008/02/04");
 script_cvs_date("$Date: 2013/04/03 22:02:31 $");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe",value:"cpe:/a:symantec:backupexec_system_recovery");
 script_end_attributes();

  script_category(ACT_ATTACK);
  script_family(english:"CGI abuses");

  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");

  script_dependencies("http_version.nasl");
  script_require_ports("Services/www", 8080, 8443);

  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");
include("http.inc");


port = get_http_port(default:8080);

banner = get_http_banner(port:port);
if ("Apache-Coyote" >!< banner) exit(0, "The web server on port "+port+" is not Apache-Coyote");


w = http_send_recv3(method:"GET", port:port, item:"/axis/FileUpload");
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);
if ("HTTP method GET is not supported by this URL" >!< res) exit(0);

# path does not exist -> exception
# fixed version exit due to ".."
fname = string("nessus-", unixtime() ,".jsp");
path  = string("nessus-", unixtime());


bound = "nessus";
boundary = string("--", bound);

postdata = string(
      boundary, "\r\n", 
      'Content-Disposition: form-data; name="path"\r\n',
      "\r\n",
      path, "\r\n",

      boundary, "\r\n", 
      'Content-Disposition: form-data; name="log_file"; filename="', fname, '"', "\r\n",
      "Content-Type: application/octet-stream\r\n",
      "\r\n",
      "NESSUS\r\n",

      boundary, "--", "\r\n"
    );

w = http_send_recv3(method:"POST", port: port, item: "/axis/FileUpload",
  content_type: "multipart/form-data; boundary="+bound,
  data: postdata);
if (isnull(w)) exit(1, "The web server on port "+port+" did not answer");
res = strcat(w[0], w[1], '\r\n', w[2]);

msg = string(path, "\\", fname, " (The system cannot find the path specified");
if (msg >< res)
  security_hole(port);
