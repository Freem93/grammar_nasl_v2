#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
 script_id(10072);
 script_version("$Revision: 1.27 $");
 script_cvs_date("$Date: 2015/09/24 21:08:39 $");

 script_cve_id("CVE-1999-0198");
 script_osvdb_id(63);

 script_name(english:"Finger .@host Unused Account Disclosure");
 script_summary(english:"Finger .@host feature");
 
 script_set_attribute(attribute:"synopsis", value:
"The finger service running on the remote host has an information
disclosure vulnerability.");
 script_set_attribute(attribute:"description", value:
"It is possible to force the remote finger daemon to display a list of
accounts that have never been used by issuing the request :

  finger .@target

A remote attacker could use this information to guess which operating
system is running or mount further attacks against these accounts.");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5a66556");
 script_set_attribute(attribute:"solution", value:"Disable or filter access to the finger daemon.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"1995/01/01");

 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"exploited_by_nessus", value:"true");
  script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_family(english:"Misc.");

 script_copyright(english:"This script is Copyright (C) 1999-2015 Tenable Network Security, Inc.");

 script_dependencies("find_service1.nasl", "finger.nasl");
 script_require_ports("Services/finger", 79);
 exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");


port = get_service(svc:"finger", default:79, exit_on_fail:TRUE);

soc = open_sock_tcp(port);
if (!soc) exit(1, "Failed to open a socket on port "+port+".");

# Cisco
data = recv(socket:soc, length:2048, timeout:5);
if (data) exit(0, "The service listening on port "+port+" sent a spontaneous header.");
  
buf = string(".\r\n");
send(socket:soc, data:buf);
data = recv(socket:soc, length:65535);
close(soc);

if (strlen(data) < 100) exit(0, "The service listening on port "+port+" sent a response of less than 100 characters.");

data_low = tolower(data);
if (
  !("such user" >< data_low) && 
  !("doesn't exist" >< data_low) && 
  !("???" >< data_low) &&
  !("welcome to" >< data_low) &&
  !("http/1.1 400 " >< data_low)
)
{
  set_kb_item(name:"finger/.@host", value:TRUE);

  if (report_verbosity > 0)
  {
    report = 
      '\nNessus was able to obtain a list of the following accounts : ' +
      '\n' + 
      data + 
     '\n';
    security_warning(port:port, extra:report);
  }
  else security_warning(port);
  exit(0);
}
else exit(0, "The service listening on port "+port+" is not affected.");
