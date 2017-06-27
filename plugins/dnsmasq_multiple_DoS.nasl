#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
 script_id(34111);
 script_version("$Revision: 1.15 $");
 script_cvs_date("$Date: 2015/12/21 20:44:57 $");

 script_cve_id("CVE-2008-3350");
 script_bugtraq_id(31017);
 script_osvdb_id(47509, 49083, 49084);

 script_name(english:"dnsmasq < 2.45 Multiple Remote DoS");
 script_summary(english:"Checks the version of dnsmasq");

 script_set_attribute(attribute:"synopsis", value:
"The remote DNS / DHCP service is affected by multiple denial of
service vulnerabilities.");
 script_set_attribute(attribute:"description", value:
"The remote host is running dnsmasq, a DHCP and DNS server.

The version of dnsmasq installed on the remote host reports itself as
2.43. This version reportedly is affected by 3 denial of service
issues :

  - The application can crash when an unknown client
    attempts to renew a DHCP lease.

  - The application may crash when a host which doesn't
    have a lease does a 'DHCPINFORM'.

  - There is a crash vulnerability in the netlink code.");
 script_set_attribute(attribute:"see_also", value:"http://www.thekelleys.org.uk/dnsmasq/CHANGELOG");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?e8cca54d");
 script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5db6c7d4");
 script_set_attribute(attribute:"solution", value:"Upgrade to dnsmasq 2.45 or later.");
 script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
 script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
 script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
 script_set_attribute(attribute:"exploit_available", value:"false");

 script_set_attribute(attribute:"plugin_publication_date", value:"2008/09/08");

 script_set_attribute(attribute:"potential_vulnerability", value:"true");
 script_set_attribute(attribute:"plugin_type", value:"remote");
 script_set_attribute(attribute:"cpe", value:"cpe:/a:thekelleys:dnsmasq");
 script_end_attributes();

 script_category(ACT_GATHER_INFO);
 script_copyright(english:"This script is Copyright (C) 2008-2015 Tenable Network Security, Inc.");
 script_family(english:"DNS");

 script_dependencie("bind_version.nasl");
 script_require_keys("bind/version", "Settings/ParanoidReport");

 exit(0);
}

include("audit.inc");
include("global_settings.inc");

if (report_paranoia < 2) audit(AUDIT_PARANOID);

# dnsmasq always replies to BIND.VERSION
vers = get_kb_item("bind/version");
if ( vers && vers == "dnsmasq-2.43" )
	security_warning(port:53, proto:"udp");
