#
# (C) Tenable Network Security, Inc.
#

################
# References
################
#
# http://www.securityfocus.com/bid/158/
# Exceed Denial of Service Vulnerability
# CVE-1999-1196


include("compat.inc");

if(description)
{
 script_id(17296);
 script_version ("$Revision: 1.16 $");

 script_cve_id("CVE-1999-1196");
 script_bugtraq_id(158);
 script_osvdb_id(11215);
 
 script_name(english:"Network Service Malformed Data Remote DoS");
 
 script_set_attribute(attribute:"synopsis", value:
"The remote service is vulnerable to a denial of service attack." );
 script_set_attribute(attribute:"description", value:
"It was possible to crash the remote service by sending it a few
kilobytes of random data. 

An attacker may use this flaw to make this service crash continuously,
preventing this service from working properly.  It may also be
possible to exploit this flaw to execute arbitrary code on this host." );
 script_set_attribute(attribute:"solution", value:
"Upgrade your software or contact your vendor and inform it of this 
vulnerability." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:ND");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value: "2005/03/08");
 script_set_attribute(attribute:"vuln_publication_date", value: "1999/04/27");
 script_cvs_date("$Date: 2011/03/11 21:52:38 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 script_summary(english: "Sends random data to the remote service");
 
 # Maybe we should set this to ACT_DESTRUCTIVE_ATTACK only?
 script_category(ACT_DENIAL);
 
 script_copyright(english:"This script is Copyright (C) 2005-2011 Tenable Network Security, Inc.");
 script_family(english: "Denial of Service");
 script_dependencie("find_service1.nasl", "find_service2.nasl");
 exit(0);
}

#
include("global_settings.inc");
include("misc_func.inc");

beurk = '';
for (i = 0; i < 256; i ++)
 beurk = strcat(beurk, 
  raw_string(rand() % 256), raw_string(rand() % 256),
  raw_string(rand() % 256), raw_string(rand() % 256),
  raw_string(rand() % 256), raw_string(rand() % 256),
  raw_string(rand() % 256), raw_string(rand() % 256));
# 2 KB

ports = get_kb_list("Ports/tcp/*");
if (isnull(ports)) exit(0);

foreach port (keys(ports))
{
 port = int(port - "Ports/tcp/");
 soc = open_sock_tcp(port);
 if (soc)
 {
   send(socket: soc, data: beurk);
   close(soc);

  # Is the service still alive?
  # Retry just in case it is rejecting connections for a while
  for (i = 1; i <= 3; i ++)
  {
    soc = open_sock_tcp(port);
    if (soc) break;
    sleep(i);
  }
  if (! soc)
  {
   if (service_is_dead(port: port, exit: 0) > 0)
     security_hole(port);
  }
  else
   close(soc);
 }
}
