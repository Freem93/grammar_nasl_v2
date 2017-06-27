#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Cisco Security Advisory cisco-sa-20130925-rsvp.
# The text itself is copyright (C) Cisco
#

include("compat.inc");

if (description)
{
  script_id(70312);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/07/28 12:52:06 $");

  script_cve_id("CVE-2013-5478");
  script_bugtraq_id(62646);
  script_osvdb_id(97735);
  script_xref(name:"CISCO-BUG-ID", value:"CSCuf17023");
  script_xref(name:"CISCO-SA", value:"cisco-sa-20130925-rsvp");

  script_name(english:"Cisco IOS XE Software Resource Reservation Protocol Interface Queue Wedge Vulnerability (cisco-sa-20130925-rsvp)");
  script_summary(english:"Checks the IOS XE version.");

  script_set_attribute(
    attribute:"synopsis",
    value:"The remote device is missing a vendor-supplied security patch."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A vulnerability in the Resource Reservation Protocol (RSVP) feature
of Cisco IOS XE Software allows an unauthenticated, remote attacker to
trigger an interface queue wedge on the affected device. The
vulnerability is due to improper parsing of UDP RSVP packets. An
attacker can exploit this vulnerability by sending UDP port 1698 RSVP
packets to the vulnerable device. An exploit can cause Cisco IOS XE
software to incorrectly process incoming packets, resulting in an
interface queue wedge, which can lead to loss of connectivity, loss
of routing protocol adjacency, and other denial of service (DoS)
conditions. Cisco has released free software updates that address this
vulnerability. Workarounds that mitigate this vulnerability are
available.

Note that this plugin checks for an affected IOS XE version and does
not attempt to perform any additional validity checks."
  );
  # http://tools.cisco.com/security/center/content/CiscoSecurityAdvisory/cisco-sa-20130925-rsvp
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4a057824"
  );
  script_set_attribute(
    attribute:"solution",
    value:
"Apply the relevant patch referenced in Cisco security advisory
cisco-sa-20130925-rsvp."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:cisco:ios_xe");

  script_set_attribute(attribute:"vuln_publication_date", value:"2013/09/25");
  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
  script_family(english:"CISCO");

  script_dependencies("cisco_ios_xe_version.nasl");
  script_require_keys("Host/Cisco/IOS-XE/Version");

  exit(0);
}

include("audit.inc");
include("cisco_func.inc");

flag = 0;

version = get_kb_item_or_exit("Host/Cisco/IOS-XE/Version");
if (version =~ '^3\\.2(\\.[0-9]+)?S$') flag++;
else if (version =~ '^3\\.3(\\.[0-9]+)?S$') flag++;
else if ((version =~ '^3\\.4(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.4.6S') == -1)) flag++;
else if (version =~ '^3\\.5(\\.[0-9]+)?S$') flag++;
else if (version =~ '^3\\.6(\\.[0-9]+)?S$') flag++;
else if ((version =~ '^3\\.7(\\.[0-9]+)?S$') && (cisco_gen_ver_compare(a:version,b:'3.7.4S') == -1)) flag++;
else if (version =~ '^3\\.8(\\.[0-9]+)?S$') flag++;

if (flag)
{
  security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
