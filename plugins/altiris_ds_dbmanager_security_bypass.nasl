#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(40822);
  script_version("$Revision: 1.9 $");

  script_cve_id("CVE-2009-3107");
  script_bugtraq_id(36110);
  script_osvdb_id(57458);
  script_xref(name:"Secunia", value:"36502");

  script_name(english:"Altiris Deployment Solution Server DB Manager Unauthenticated Command Execution");
  script_summary(english:"Sends a command to the DB Manager service");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host has a program that is affected by a security
bypass vulnerability."  );
  script_set_attribute(attribute:"description", value:
"The remote host is running a vulnerable version of Altiris Deployment
Solution Server.  Authentication is not required prior to sending
commands to the DB Manager service.  A remote attacker could exploit
this to modify or read data from the Altiris database."  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?54b8b8c5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f914235e"
  );
  script_set_attribute(
    attribute:"solution",
    value:"Upgrade to Altiris Deployment Solution Server 6.9.430 or later."
  );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");
 script_cwe_id(264);
  script_set_attribute(
    attribute:"vuln_publication_date",
    value:"2009/08/26"
  );
  script_set_attribute(
    attribute:"patch_publication_date",
    value:"2009/08/26"
  );
  script_set_attribute(
    attribute:"plugin_publication_date",
    value:"2009/08/31"
  );
 script_cvs_date("$Date: 2015/09/24 20:59:28 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");

  script_dependencies("altiris_deployment_server_detect.nasl");
  script_require_ports("Services/unknown", 505);

  exit(0);
}


include("global_settings.inc");
include("misc_func.inc");
include("byte_func.inc");


# If Altiris DS wasn't detected on port 402, we can assume the system isn't
# listening on port 505 either (unless we're paranoid)
#if (report_paranoia < 2 && !get_kb_item("Services/axengine"))
#  exit(0, "Altiris DS server wasn't detected on the remote host");

port = 505;
if (!get_tcp_port_state(port)) exit(0, "TCP port 505 is not open");

soc = open_sock_tcp(port);
if (!soc) exit(1, "Unable to create socket");

cmd_name = 'GetPrivilege';
req = 'Request=' + cmd_name + '\n' + mkbyte(0);
send(socket:soc, data:req);
res = recv(socket:soc, length:1024);
close(soc);

if (isnull(res)) exit(1, "No response was received");

# The fix is to require authentication before processing any command requests
if ('Result=AuthFailed' >< res) exit(0, "The host is not affected");

if ('Result=Success' >< res)
{
  if (report_verbosity > 0)
  {
    report = "
Nessus was able to successfully execute the '" + cmd_name + "' command.
";

    # Only include the command output if we're verbose
    if (report_verbosity > 1)
    {
      report += 
        '\nThe server responded with the following output :\n\n' + 
        str_replace(string:res, find: '\0', replace:'') + '\n';
    }

    security_hole(port:port, extra:report);
  }
  else security_hole(port);

  exit(0); 
}

# If we made it this far, the server didn't reply saying auth is required, and
# it didn't reply saying the command was executed successfully.  Therefore,
# either the command failed (possible but unexpected) or there was some other
# error.  Need to look through the server's response to get the command result.
error = NULL;

foreach line (split(res, sep: '\0'))
{
  match = eregmatch(string:line, pattern:'Result=([a-zA-Z]+)');
  if (match)
  {
    error = 'result status = ' + match[1];
    break;
  }
}

if (isnull(error)) error = 'unknown error, no result status given';
exit(1, "Unexpected response (" + error + ")");
