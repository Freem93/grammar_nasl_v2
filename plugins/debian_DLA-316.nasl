#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-316-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86155);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_cve_id("CVE-2014-8121");
  script_bugtraq_id(73038);
  script_osvdb_id(119253);

  script_name(english:"Debian DLA-316-1 : eglibc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in eglibc that may lead
to a privilege escalation or denial of service.

Glibc pointer guarding weakness

A weakness in the dynamic loader prior has been found. The issue is
that the LD_POINTER_GUARD in the environment is not sanitized allowing
local attackers easily to bypass the pointer guarding protection on
set-user-ID and set-group-ID programs.

Potential application crash due to overread in fnmatch

When processing certain malformed patterns, fnmatch can skip over the
NUL byte terminating the pattern. This can potentially result in an
application crash if fnmatch hits an unmapped page before encountering
a NUL byte.

_IO_wstr_overflow integer overflow

A miscalculation in _IO_wstr_overflow could potentially be exploited
to overflow a buffer.

CVE-2014-8121

DB_LOOKUP in nss_files/files-XXX.c in the Name Service Switch (NSS) in
GNU C Library (aka glibc or libc6) 2.21 and earlier does not properly
check if a file is open, which allows remote attackers to cause a
denial of service (infinite loop) by performing a look-up while the
database is iterated over the database, which triggers the file
pointer to be reset.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 2.11.3-4+deb6u7.

We recommend that you update your packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00011.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/eglibc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc-source");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc-dev-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-amd64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-dev-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i386");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-pic");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-prof");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libc6-xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-dns-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnss-files-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:locales-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nscd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/28");
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
if (deb_check(release:"6.0", prefix:"eglibc-source", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"glibc-doc", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc-bin", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc-dev-bin", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-amd64", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dbg", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-amd64", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-i386", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i386", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i686", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-pic", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-prof", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-udeb", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-xen", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-dns-udeb", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-files-udeb", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"locales", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"locales-all", reference:"2.11.3-4+deb6u7")) flag++;
if (deb_check(release:"6.0", prefix:"nscd", reference:"2.11.3-4+deb6u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
