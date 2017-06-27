#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-451-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90869);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2016-0636", "CVE-2016-0686", "CVE-2016-0687", "CVE-2016-0695", "CVE-2016-3425", "CVE-2016-3426", "CVE-2016-3427");
  script_osvdb_id(98536, 137301, 137302, 137303, 137305, 137306, 137308);

  script_name(english:"Debian DLA-451-1 : openjdk-7 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in OpenJDK, an
implementation of the Oracle Java platform, resulting in breakouts of
the Java sandbox, denial of service or information disclosure.

For Debian 7 'Wheezy', these problems have been fixed in version
7u101-2.6.6-2~deb7u1.

We recommend that you upgrade your openjdk-7 packages.

Please note that OpenJDK 7 will be made the new default Java
implementation on 26 June 2016. For further information please refer
to

  https://wiki.debian.org/LTS/Wheezy

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openjdk-7"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/Wheezy"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:C/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-7-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-7-jre-jamvm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-7-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/04");
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
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-cacao", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"icedtea-7-jre-jamvm", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-dbg", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-demo", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-doc", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jdk", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-headless", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-lib", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-jre-zero", reference:"7u101-2.6.6-2~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"openjdk-7-source", reference:"7u101-2.6.6-2~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
