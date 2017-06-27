#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
 script_id(10804);
 script_version ("$Revision: 1.13 $");
 script_cvs_date("$Date: 2013/01/25 01:19:10 $");
 script_cve_id("CVE-2001-0913");
 script_osvdb_id(671);

 script_name(english:"Network Solutions Rwhoisd Syslog Remote Format String");
 
 script_set_attribute(attribute:"synopsis", value:
"Arbitrary code may be run on the remote server." );
 script_set_attribute(attribute:"description", value:
"The remote rwhois daemon is vulnerable to a format string attack when 
supplied malformed arguments to a malformed request (such as %p%p%p).

An attacker may use this flaw to gain a shell on this host.

*** Note that Nessus solely relied on the banner version to
*** issue this warning. If you manually patched rwhoisd, you
*** may not be vulnerable to this flaw" );
 script_set_attribute(attribute:"solution", value:
"Disable this service or upgrade to version 1.5.7.3 or newer" );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");


 script_set_attribute(attribute:"plugin_publication_date", value: "2001/11/25");
 script_set_attribute(attribute:"vuln_publication_date", value: "2001/11/22");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Checks the version of rwhois");
 script_category(ACT_ATTACK);
 script_copyright(english:"This script is Copyright (C) 2001-2013 Tenable Network Security, Inc.");
 script_family(english: "Gain a shell remotely");
 script_dependencie("find_service1.nasl");
 script_require_ports("Services/rwhois", 4321);
 exit(0);
}

#
# The script code starts here
#

port = 4321;
if(get_port_state(port))
{
 soc = open_sock_tcp(port);
 if(soc)
 {
  # There's no way to determine remotely if the service if vulnerable
  # or not.
  r = recv(socket:soc, length:4096);
  if(egrep(pattern:"V-1\.([0-4]|5\.([0-6]|7\.[0-2]))", 
         string:r))security_hole(4321);
 }
}
