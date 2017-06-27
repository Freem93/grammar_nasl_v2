#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3535. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90278);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-2385");
  script_osvdb_id(134586);
  script_xref(name:"DSA", value:"3535");

  script_name(english:"Debian DSA-3535-1 : kamailio - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Stelios Tsampas discovered a buffer overflow in the Kamailio SIP proxy
which might result in the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/kamailio"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3535"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kamailio packages.

For the stable distribution (jessie), this problem has been fixed in
version 4.2.0-2+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kamailio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"8.0", prefix:"kamailio", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-autheph-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-berkeley-bin", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-berkeley-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-carrierroute-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-cpl-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-dbg", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-dnssec-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-extra-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-geoip-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-ims-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-java-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-json-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-ldap-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-lua-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-memcached-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-mono-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-mysql-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-outbound-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-perl-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-postgres-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-presence-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-python-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-radius-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-redis-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-sctp-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-snmpstats-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-sqlite-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-tls-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-unixodbc-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-utils-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-websocket-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-xml-modules", reference:"4.2.0-2+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"kamailio-xmpp-modules", reference:"4.2.0-2+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
