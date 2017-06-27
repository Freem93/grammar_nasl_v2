#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-245. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15082);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2013/05/18 00:02:54 $");

  script_cve_id("CVE-2003-0039");
  script_bugtraq_id(6628);
  script_xref(name:"CERT", value:"149953");
  script_xref(name:"DSA", value:"245");

  script_name(english:"Debian DSA-245-1 : dhcp3 - ignored counter boundary");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Florian Lohoff discovered a bug in the dhcrelay causing it to send a
continuing packet storm towards the configured DHCP server(s) in case
of a malicious BOOTP packet, such as sent from buggy Cisco switches.

When the dhcp-relay receives a BOOTP request it forwards the request
to the DHCP server using the broadcast MAC address ff:ff:ff:ff:ff:ff
which causes the network interface to reflect the packet back into the
socket. To prevent loops the dhcrelay checks whether the relay-address
is its own, in which case the packet would be dropped. In combination
with a missing upper boundary for the hop counter an attacker can
force the dhcp-relay to send a continuing packet storm towards the
configured dhcp server(s).

This patch introduces a new command line switch -c maxcount and people
are advised to start the dhcp-relay with dhcrelay -c 10or a smaller
number, which will only create that many packets.

The dhcrelay program from the 'dhcp' package does not seem to be
affected since DHCP packets are dropped if they were apparently
relayed already."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-245"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dhcp3 package when you are using the dhcrelay server.

For the stable distribution (woody) this problem has been fixed in
version 3.0+3.0.1rc9-2.2.

The old stable distribution (potato) does not contain dhcp3 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dhcp3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
  script_family(english:"Debian Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Debian/release", "Host/Debian/dpkg-l");

  exit(0);
}


include("audit.inc");
include("debian_package.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Debian/release")) audit(AUDIT_OS_NOT, "Debian");
if (!get_kb_item("Host/Debian/dpkg-l")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (deb_check(release:"3.0", prefix:"dhcp3-client", reference:"3.0+3.0.1rc9-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"dhcp3-common", reference:"3.0+3.0.1rc9-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"dhcp3-dev", reference:"3.0+3.0.1rc9-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"dhcp3-relay", reference:"3.0+3.0.1rc9-2.2")) flag++;
if (deb_check(release:"3.0", prefix:"dhcp3-server", reference:"3.0+3.0.1rc9-2.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
