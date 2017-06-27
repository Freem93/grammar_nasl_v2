#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");

if(description)
{
  script_id(11484);
  script_bugtraq_id(2070, 6828, 7200);
  script_osvdb_id(1683, 10748, 10749);
  script_cve_id("CVE-2001-0040", "CVE-2003-0098", "CVE-2003-0099");
  
  script_version ("$Revision: 1.18 $");
 
  script_name(english:"APC < 3.8.0 apcupsd Multiple Vulnerabilities");
  script_summary(english:"Checks the version of apcupsd");

 script_set_attribute(attribute:"synopsis", value:
"The remote host is running an application which is affected by
multiple vulnerabilities." );
 script_set_attribute(attribute:"description", value:
"The remote host is running the apcupsd client which, according to its
version number, is affected by multiple vulnerabilities :

  - The configuration file '/var/run/apcupsd.pid' is by
    default world-writable. A local attacker could re-write 
    this file with other process IDs in order to crash the
    affected system.

  - An issue exists in the 'log_event' function which a
    local attacker could exploit in order to execute
    arbitrary code.

  - Several buffer overflow vulnerabilities have been
    reported which a remote attacker could exploit in order
    to execute arbitrary code on the remote host.

*** Nessus solely relied on the version number of the 
*** remote server, so this might be a false positive" );
 script_set_attribute(attribute:"see_also", value:"http://seclists.org/bugtraq/2000/Dec/102" );
 script_set_attribute(attribute:"see_also", value:"http://www.novell.com/linux/security/advisories/2003_022_apcupsd.html" );
 script_set_attribute(attribute:"solution", value:
"Upgrading to acpupsd version 3.8.0 or newer reportedly fixes the issue." );
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
 script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2003/03/26");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/12/06");
 script_cvs_date("$Date: 2016/11/11 19:58:29 $");
script_set_attribute(attribute:"plugin_type", value:"remote");
script_end_attributes();

 
  script_category(ACT_GATHER_INFO);
 
  script_copyright(english:"This script is Copyright (C) 2003-2016 Tenable Network Security, Inc.");
  script_family(english:"Gain a shell remotely");
  script_dependencie("find_service1.nasl", "apcnisd_detect.nasl");
  script_require_ports("Services/apcnisd", 7000);

  exit(0);
}

port = get_kb_item("Services/apcnisd");
if (! port) port = 7000;
if (! get_port_state(port)) exit(0);

soc = open_sock_tcp(port);
if(!soc)exit(0);
req = raw_string(0x00, 0x06) + "status";
send(socket:soc, data:req);
r = recv(socket:soc, length:4096);
if("APC" >< r && "MODEL" >< r)
{
  r = strstr(r, "RELEASE");
  if(ereg(pattern:"RELEASE.*: (3\.([0-7]\..*|8\.[0-5][^0-9]|10\.[0-4])|[0-2]\..*)", string:r))
       security_hole(port);

}
