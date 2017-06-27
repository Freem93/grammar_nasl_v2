#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-410-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88580);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-7575", "CVE-2015-8126", "CVE-2015-8472", "CVE-2016-0402", "CVE-2016-0448", "CVE-2016-0466", "CVE-2016-0483", "CVE-2016-0494");
  script_osvdb_id(130175, 132305, 133156, 133157, 133159, 133160, 133161);

  script_name(english:"Debian DLA-410-1 : openjdk-6 security update (SLOTH)");
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
the Java sandbox, information disclosure, denial of service and
insecure cryptography.

CVE-2015-7575   A flaw was found in the way TLS 1.2 could use the
MD5 hash function for signing ServerKeyExchange and Client
Authentication packets during a TLS handshake.

CVE-2015-8126   Multiple buffer overflows in the (1) png_set_PLTE
and (2)   png_get_PLTE functions in libpng before 1.0.64, 1.1.x and
1.2.x   before 1.2.54, 1.3.x and 1.4.x before 1.4.17, 1.5.x before
  1.5.24, and 1.6.x before 1.6.19 allow remote attackers to cause
  a denial of service (application crash) or possibly have
  unspecified other impact via a small bit-depth value in an IHDR
  (aka image header) chunk in a PNG image.

CVE-2015-8472   Buffer overflow in the png_set_PLTE function in
libpng before   1.0.65, 1.1.x and 1.2.x before 1.2.55, 1.3.x, 1.4.x
before   1.4.18, 1.5.x before 1.5.25, and 1.6.x before 1.6.20 allows
  remote attackers to cause a denial of service (application
  crash) or possibly have unspecified other impact via a small
  bit-depth value in an IHDR (aka image header) chunk in a PNG
  image. NOTE: this vulnerability exists because of an incomplete
  fix for CVE-2015-8126.

CVE-2016-0402   Unspecified vulnerability in the Java SE and Java SE
Embedded   components in Oracle Java SE 6u105, 7u91, and 8u66 and
Java SE   Embedded 8u65 allows remote attackers to affect integrity
via   unknown vectors related to Networking.

CVE-2016-0448   Unspecified vulnerability in the Java SE and Java SE
Embedded   components in Oracle Java SE 6u105, 7u91, and 8u66, and
Java SE   Embedded 8u65 allows remote authenticated users to affect
  confidentiality via vectors related to JMX.

CVE-2016-0466   It was discovered that the JAXP component in OpenJDK
did not properly enforce the totalEntitySizeLimit limit. An attacker
able to make a Java application process a specially crafted XML file
could use this flaw to make the application consume an excessive
amount of memory.

CVE-2016-0483   Unspecified vulnerability in the Java SE, Java SE
Embedded, and   JRockit components in Oracle Java SE 6u105, 7u91,
and 8u66;   Java SE Embedded 8u65; and JRockit R28.3.8 allows remote
  attackers to affect confidentiality, integrity, and
  availability via vectors related to AWT.

CVE-2016-0494   Unspecified vulnerability in the Java SE and Java SE
Embedded   components in Oracle Java SE 6u105, 7u91, and 8u66 and
Java SE   Embedded 8u65 allows remote attackers to affect   
  confidentiality, integrity, and availability via   unknown
vectors related to 2D.

For Debian 6 'Squeeze', these problems have been fixed in version
6b38-1.13.10-1~deb6u1.

We recommend that you upgrade your openjdk-6 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openjdk-6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:L");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedtea-6-jre-cacao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-demo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-jre-lib");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-jre-zero");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openjdk-6-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/04");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/05");
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
if (deb_check(release:"6.0", prefix:"icedtea-6-jre-cacao", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-dbg", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-demo", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-doc", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jdk", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-headless", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-lib", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-jre-zero", reference:"6b38-1.13.10-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"openjdk-6-source", reference:"6b38-1.13.10-1~deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
