#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-324-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86227);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2012-3509");
  script_bugtraq_id(55281);
  script_osvdb_id(85328);

  script_name(english:"Debian DLA-324-1 : binutils security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes several issues as described below.

PR ld/12613 (no CVE assigned)

Niranjan Hasabnis discovered that passing an malformed linker script
to GNU ld, part of binutils, may result in a stack-based buffer overflow. If
the linker is used with untrusted object files, this would allow
remote attackers to cause a denial of service (crash) or possibly
privilege escalation.

CVE-2012-3509 #688951

Sang Kil Cha discovered that a buffer size calculation in libiberty,
part of binutils, may result in integer overflow and then a heap
buffer overflow. If libiberty or the commands in binutils are used to
read untrusted binaries, this would allow remote attackers to cause a
denial of service (crash) or possibly privilege escalation.

PR binutils/18750 (no CVE assigned)

Joshua Rogers reported that passing a malformed ihex (Intel
hexadecimal) file to to various commands in binutils may result in a
stack-based buffer overflow. A similar issue was found in readelf. If these
commands are used to read untrusted binaries, this would allow remote
attackers to cause a denial of service (crash) or possibly privilege
escalation.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 2.20.1-16+deb6u2.

For the oldstable distribution (wheezy) and the stable distribution
(jessie), PR ld/12613 and CVE-2012-3509 were fixed before release, and
PR binutils/18750 will be fixed in a later update.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/10/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/binutils"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"binutils", reference:"2.20.1-16+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-dev", reference:"2.20.1-16+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-doc", reference:"2.20.1-16+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-gold", reference:"2.20.1-16+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-multiarch", reference:"2.20.1-16+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-source", reference:"2.20.1-16+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
