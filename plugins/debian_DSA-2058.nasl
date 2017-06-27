#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2058. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46861);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:11 $");

  script_cve_id("CVE-2008-1391", "CVE-2009-4880", "CVE-2009-4881", "CVE-2010-0296", "CVE-2010-0830");
  script_bugtraq_id(36443, 40063);
  script_osvdb_id(65078);
  script_xref(name:"DSA", value:"2058");

  script_name(english:"Debian DSA-2058-1 : glibc, eglibc - multiple  vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the GNU C Library (aka
glibc) and its derivatives. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-1391, CVE-2009-4880, CVE-2009-4881
    Maksymilian Arciemowicz discovered that the GNU C
    library did not correctly handle integer overflows in
    the strfmon family of functions. If a user or automated
    system were tricked into processing a specially crafted
    format string, a remote attacker could crash
    applications, leading to a denial of service.

  - CVE-2010-0296
    Jeff Layton and Dan Rosenberg discovered that the GNU C
    library did not correctly handle newlines in the mntent
    family of functions. If a local attacker were able to
    inject newlines into a mount entry through other
    vulnerable mount helpers, they could disrupt the system
    or possibly gain root privileges.

  - CVE-2010-0830
    Dan Rosenberg discovered that the GNU C library did not
    correctly validate certain ELF program headers. If a
    user or automated system were tricked into verifying a
    specially crafted ELF program, a remote attacker could
    execute arbitrary code with user privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=583908"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4881"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0296"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0830"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2058"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the glibc or eglibc packages.

For the stable distribution (lenny), these problems have been fixed in
version 2.7-18lenny4 of the glibc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"glibc-doc", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"glibc-source", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-amd64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dbg", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-amd64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-i386", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-mips64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-mipsn32", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-ppc64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-s390x", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-dev-sparc64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-i386", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-i686", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-mips64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-mipsn32", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-pic", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-ppc64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-prof", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-s390x", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-sparc64", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-sparcv9b", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6-xen", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-alphaev67", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-dbg", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-dev", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-pic", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"libc6.1-prof", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"locales", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"locales-all", reference:"2.7-18lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"nscd", reference:"2.7-18lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
