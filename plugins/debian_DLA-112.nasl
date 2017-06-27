#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-112-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82096);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-8500");
  script_bugtraq_id(71590);
  script_osvdb_id(115524);

  script_name(english:"Debian DLA-112-1 : bind9 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a denial of service vulnerability in BIND, a DNS
server.

By making use of maliciously-constructed zones or a rogue server, an
attacker could exploit an oversight in the code BIND 9 used to follow
delegations in the Domain Name Service, causing BIND to issue
unlimited queries in an attempt to follow the delegation.

This can lead to resource exhaustion and denial of service (up to and
including termination of the named server process).

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/bind9"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9-host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:bind9utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dnsutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:host");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libbind9-60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libdns69");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisc62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccc60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libisccfg62");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:liblwres60");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lwresd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"bind9", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-doc", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"bind9-host", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"bind9utils", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"dnsutils", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"host", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libbind-dev", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libbind9-60", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libdns69", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libisc62", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libisccc60", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"libisccfg62", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"liblwres60", reference:"9.7.3.dfsg-1~squeeze13")) flag++;
if (deb_check(release:"6.0", prefix:"lwresd", reference:"9.7.3.dfsg-1~squeeze13")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
