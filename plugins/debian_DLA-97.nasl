#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-97-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82242);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-6656", "CVE-2014-6040", "CVE-2014-7817");
  script_bugtraq_id(69470, 69472, 71216);
  script_osvdb_id(110668, 110669, 110670, 110671, 110672, 110673, 110674, 110675, 115032);

  script_name(english:"Debian DLA-97-1 : eglibc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2012-6656

Fix validation check when converting from ibm930 to utf. When
converting IBM930 code with iconv(), if IBM930 code which includes
invalid multibyte character '0xffff' is specified, then iconv()
segfaults.

CVE-2014-6040

Crashes on invalid input in IBM gconv modules [BZ #17325] These
changes are based on the fix for BZ #14134 in commit
6e230d11837f3ae7b375ea69d7905f0d18eb79e5.

CVE-2014-7817

The function wordexp() fails to properly handle the WRDE_NOCMD flag
when processing arithmetic inputs in the form of '$((... ``))' where
'...' can be anything valid. The backticks in the arithmetic
epxression are evaluated by in a shell even if WRDE_NOCMD forbade
command substitution. This allows an attacker to attempt to pass
dangerous commands via constructs of the above form, and bypass the
WRDE_NOCMD flag. This patch fixes this by checking for WRDE_NOCMD in
exec_comm(), the only place that can execute a shell. All other checks
for WRDE_NOCMD are superfluous and removed.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00015.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/eglibc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"eglibc-source", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"glibc-doc", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc-bin", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc-dev-bin", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-amd64", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dbg", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-amd64", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-i386", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i386", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i686", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-pic", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-prof", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-udeb", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-xen", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-dns-udeb", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-files-udeb", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"locales", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"locales-all", reference:"2.11.3-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"nscd", reference:"2.11.3-4+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
