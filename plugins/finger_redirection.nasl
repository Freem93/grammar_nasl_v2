#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(10073);
 script_version("$Revision: 1.33 $");
 script_cvs_date("$Date: 2011/12/28 01:10:53 $");

 script_cve_id("CVE-1999-0105", "CVE-1999-0106");
 script_osvdb_id(64, 5769);

 script_name(english:"Finger Recursive Request Arbitrary Site Redirection");
 script_summary(english:"Finger user@host1@host2");
 
 script_set_attribute(attribute:"synopsis", value:
"It is possible to use the remote host to perform third-party host
scans.");
 script_set_attribute(attribute:"description", value:
"The remote finger service accepts redirect requests.  That is, users
can perform requests like :

		finger user@host@victim

This allows an attacker to use this computer as a relay to gather
information on a third-party network.  In addition, this type of
syntax can be used to create a denial of service condition on the
remote host.");
 script_set_attribute(attribute:"solution", value:
"Disable the remote finger daemon (comment out the 'finger' line in
/etc/inetd.conf and restart the inetd process) or upgrade it to a more
secure one." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N");

 script_set_attribute(attribute:"plugin_publication_date", value:"1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value:"1992/10/28");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_end_attributes();
 
 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2007-2011 Tenable Network Security, Inc.");
 script_family(english:"Misc.");

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

# cisco
data = recv(socket:soc, length:2048, timeout:5);
if (data) exit(0, "The service listening on port "+port+" sent a spontaneous header.");
  
buf = string("root@", get_host_name(), "\r\n");
send(socket:soc, data:buf);
data = recv(socket:soc, length:65535);
close(soc);

if (!strlen(data)) exit(0, "The service listening on port "+port+" did not respond.");

data_low = tolower(data);
  
if (
  !("such user" >< data_low) && 
  !("doesn't exist" >< data_low) && 
  !("???" >< data_low) &&
  !("welcome to" >< data_low) && 
  !("forward" >< data_low) &&
  !("http/1.1 400 " >< data_low)
)
{
  set_kb_item(name:"finger/user@host1@host2", value:TRUE);
  security_warning(port);
}
