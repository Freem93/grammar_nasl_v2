#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2551. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(62225);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2012-3955");
  script_bugtraq_id(55530);
  script_osvdb_id(85424);
  script_xref(name:"DSA", value:"2551");

  script_name(english:"Debian DSA-2551-1 : isc-dhcp - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Glen Eustace discovered that the ISC DHCP server, a server for
automatic IP address assignment, is not properly handling changes in
the expiration times of a lease. An attacker may use this flaw to
crash the service and cause denial of service conditions, by reducing
the expiration time of an active IPv6 lease."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/isc-dhcp"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2551"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the isc-dhcp packages.

For the stable distribution (squeeze), this problem has been fixed in
version 4.1.1-P1-15+squeeze8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:isc-dhcp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/09/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/09/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"dhcp3-client", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-common", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-dev", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-relay", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"dhcp3-server", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-dbg", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-client-udeb", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-common", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-dev", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-relay-dbg", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-dbg", reference:"4.1.1-P1-15+squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"isc-dhcp-server-ldap", reference:"4.1.1-P1-15+squeeze8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
