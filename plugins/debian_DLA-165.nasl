#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-165-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(82149);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/04/28 18:15:19 $");

  script_cve_id("CVE-2012-3405", "CVE-2012-3406", "CVE-2012-3480", "CVE-2012-4412", "CVE-2012-4424", "CVE-2013-0242", "CVE-2013-1914", "CVE-2013-4237", "CVE-2013-4332", "CVE-2013-4357", "CVE-2013-4458", "CVE-2013-4788", "CVE-2013-7423", "CVE-2013-7424", "CVE-2014-4043", "CVE-2015-1472", "CVE-2015-1473");
  script_bugtraq_id(54374, 54982, 55462, 55543, 57638, 58839, 61183, 61729, 62324, 63299, 67992, 68006, 72428, 72498, 72499, 72710, 72844);
  script_osvdb_id(84710, 88152, 89747, 92038, 96318, 97246, 97247, 97248, 98142, 98836, 108023, 117751, 117873, 117874);

  script_name(english:"Debian DLA-165-1 : eglibc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in eglibc, Debian's version of
the GNU C library.

#553206 CVE-2015-1472 CVE-2015-1473

The scanf family of functions do not properly limit stack allocation,
which allows context-dependent attackers to cause a denial of service
(crash) or possibly execute arbitrary code.

CVE-2012-3405

The printf family of functions do not properly calculate a buffer
length, which allows context-dependent attackers to bypass the
FORTIFY_SOURCE format-string protection mechanism and cause a denial
of service.

CVE-2012-3406

The printf family of functions do not properly limit stack allocation,
which allows context-dependent attackers to bypass the FORTIFY_SOURCE
format-string protection mechanism and cause a denial of service
(crash) or possibly execute arbitrary code via a crafted format
string.

CVE-2012-3480

Multiple integer overflows in the strtod, strtof, strtold, strtod_l,
and other related functions allow local users to cause a denial of
service (application crash) and possibly execute arbitrary code via a
long string, which triggers a stack-based buffer overflow.

CVE-2012-4412

Integer overflow in the strcoll and wcscoll functions allows
context-dependent attackers to cause a denial of service (crash) or
possibly execute arbitrary code via a long string, which triggers a
heap-based buffer overflow.

CVE-2012-4424

Stack-based buffer overflow in the strcoll and wcscoll functions
allows context-dependent attackers to cause a denial of service
(crash) or possibly execute arbitrary code via a long string that
triggers a malloc failure and use of the alloca function.

CVE-2013-0242

Buffer overflow in the extend_buffers function in the regular
expression matcher allows context-dependent attackers to cause a
denial of service (memory corruption and crash) via crafted multibyte
characters.

CVE-2013-1914 CVE-2013-4458

Stack-based buffer overflow in the getaddrinfo function allows remote
attackers to cause a denial of service (crash) via a hostname or IP
address that triggers a large number of domain conversion results.

CVE-2013-4237

readdir_r allows context-dependent attackers to cause a denial of
service (out-of-bounds write and crash) or possibly execute arbitrary
code via a malicious NTFS image or CIFS service.

CVE-2013-4332

Multiple integer overflows in malloc/malloc.c allow context-dependent
attackers to cause a denial of service (heap corruption) via a large
value to the pvalloc, valloc, posix_memalign, memalign, or
aligned_alloc functions.

CVE-2013-4357

The getaliasbyname, getaliasbyname_r, getaddrinfo, getservbyname,
getservbyname_r, getservbyport, getservbyport_r, and glob functions do
not properly limit stack allocation, which allows context-dependent
attackers to cause a denial of service (crash) or possibly execute
arbitrary code.

CVE-2013-4788

When the GNU C library is statically linked into an executable, the
PTR_MANGLE implementation does not initialize the random value for the
pointer guard, so that various hardening mechanisms are not effective.

CVE-2013-7423

The send_dg function in resolv/res_send.c does not properly reuse file
descriptors, which allows remote attackers to send DNS queries to
unintended locations via a large number of requests that trigger a
call to the getaddrinfo function.

CVE-2013-7424

The getaddrinfo function may attempt to free an invalid pointer when
handling IDNs (Internationalised Domain Names), which allows remote
attackers to cause a denial of service (crash) or possibly execute
arbitrary code.

CVE-2014-4043

The posix_spawn_file_actions_addopen function does not copy its path
argument in accordance with the POSIX specification, which allows
context-dependent attackers to trigger use-after-free vulnerabilities.

For the oldstable distribution (squeeze), these problems have been
fixed in version 2.11.3-4+deb6u5.

For the stable distribution (wheezy), these problems were fixed in
version 2.13-38+deb7u8 or earlier.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/03/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/eglibc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/06");
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
if (deb_check(release:"6.0", prefix:"eglibc-source", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"glibc-doc", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc-bin", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc-dev-bin", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-amd64", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dbg", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-amd64", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-i386", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i386", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i686", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-pic", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-prof", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-udeb", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-xen", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-dns-udeb", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-files-udeb", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"locales", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"locales-all", reference:"2.11.3-4+deb6u5")) flag++;
if (deb_check(release:"6.0", prefix:"nscd", reference:"2.11.3-4+deb6u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
