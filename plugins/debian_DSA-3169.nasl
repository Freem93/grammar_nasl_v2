#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3169. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81448);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/02/28 05:39:56 $");

  script_cve_id("CVE-2012-3406", "CVE-2013-7424", "CVE-2014-4043", "CVE-2014-9402", "CVE-2015-1472", "CVE-2015-1473");
  script_bugtraq_id(54374, 68006, 71670, 72428, 72499, 72710);
  script_xref(name:"DSA", value:"3169");

  script_name(english:"Debian DSA-3169-1 : eglibc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in eglibc, Debian's version of
the GNU C library :

  - CVE-2012-3406
    The vfprintf function in stdio-common/vfprintf.c in GNU
    C Library (aka glibc) 2.5, 2.12, and probably other
    versions does not 'properly restrict the use of' the
    alloca function when allocating the SPECS array, which
    allows context-dependent attackers to bypass the
    FORTIFY_SOURCE format-string protection mechanism and
    cause a denial of service (crash) or possibly execute
    arbitrary code via a crafted format string using
    positional parameters and a large number of format
    specifiers, a different vulnerability than CVE-2012-3404
    and CVE-2012-3405.

  - CVE-2013-7424
    An invalid free flaw was found in glibc's getaddrinfo()
    function when used with the AI_IDN flag. A remote
    attacker able to make an application call this function
    could use this flaw to execute arbitrary code with the
    permissions of the user running the application. Note
    that this flaw only affected applications using glibc
    compiled with libidn support.

  - CVE-2014-4043
    The posix_spawn_file_actions_addopen function in glibc
    before 2.20 does not copy its path argument in
    accordance with the POSIX specification, which allows
    context-dependent attackers to trigger use-after-free
    vulnerabilities.

  - CVE-2014-9402
    The getnetbyname function in glibc 2.21 or earlier will
    enter an infinite loop if the DNS backend is activated
    in the system Name Service Switch configuration, and the
    DNS resolver receives a positive answer while processing
    the network name.

  - CVE-2015-1472 / CVE-2015-1473
    Under certain conditions wscanf can allocate too little
    memory for the to-be-scanned arguments and overflow the
    allocated buffer. The incorrect use of
    '__libc_use_alloca (newsize)' caused a different (and
    weaker) policy to be enforced which could allow a denial
    of service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=681888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=751774"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=775572"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=777197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3405"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-7424"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4043"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9402"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/eglibc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3169"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the eglibc packages.

For the stable distribution (wheezy), these issues are fixed in
version 2.13-38+deb7u8 of the eglibc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/02/24");
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
if (deb_check(release:"7.0", prefix:"eglibc-source", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"glibc-doc", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc-bin", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc-dev-bin", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dbg", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev-i386", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i386", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i686", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-pic", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-prof", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-amd64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dbg", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-amd64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-i386", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mips64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mipsn32", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-ppc64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390x", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-sparc64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i386", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i686", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-loongson2f", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mips64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mipsn32", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-pic", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-ppc64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-prof", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390x", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-sparc64", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-xen", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dbg", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dev", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-pic", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-prof", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"locales", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"locales-all", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"multiarch-support", reference:"2.13-38+deb7u8")) flag++;
if (deb_check(release:"7.0", prefix:"nscd", reference:"2.13-38+deb7u8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
