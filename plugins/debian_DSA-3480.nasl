#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3480. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(88767);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2014-8121", "CVE-2015-1781", "CVE-2015-7547", "CVE-2015-8776", "CVE-2015-8777", "CVE-2015-8778", "CVE-2015-8779");
  script_xref(name:"DSA", value:"3480");
  script_xref(name:"IAVA", value:"2016-A-0053");
  script_xref(name:"TRA", value:"TRA-2017-08");

  script_name(english:"Debian DSA-3480-1 : eglibc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in the GNU C Library, eglibc.

The CVE-2015-7547 vulnerability listed below is considered to have
critical impact.

  - CVE-2014-8121
    Robin Hack discovered that the nss_files database did
    not correctly implement enumeration interleaved with
    name-based or ID-based lookups. This could cause the
    enumeration enter an endless loop, leading to a denial
    of service.

  - CVE-2015-1781
    Arjun Shankar discovered that the _r variants of host
    name resolution functions (like gethostbyname_r), when
    performing DNS name resolution, suffered from a buffer
    overflow if a misaligned buffer was supplied by the
    applications, leading to a crash or, potentially,
    arbitrary code execution. Most applications are not
    affected by this vulnerability because they use aligned
    buffers.

  - CVE-2015-7547
    The Google Security Team and Red Hat discovered that the
    eglibc host name resolver function, getaddrinfo, when
    processing AF_UNSPEC queries (for dual A/AAAA lookups),
    could mismanage its internal buffers, leading to a
    stack-based buffer overflow and arbitrary code
    execution. This vulnerability affects most applications
    which perform host name resolution using getaddrinfo,
    including system services.

  - CVE-2015-8776
    Adam Nielsen discovered that if an invalid separated
    time value is passed to strftime, the strftime function
    could crash or leak information. Applications normally
    pass only valid time information to strftime; no
    affected applications are known.

  - CVE-2015-8777
    Hector Marco-Gisbert reported that LD_POINTER_GUARD was
    not ignored for SUID programs, enabling an unintended
    bypass of a security feature. This update causes eglibc
    to always ignore the LD_POINTER_GUARD environment
    variable.

  - CVE-2015-8778
    Szabolcs Nagy reported that the rarely-used hcreate and
    hcreate_r functions did not check the size argument
    properly, leading to a crash (denial of service) for
    certain arguments. No impacted applications are known at
    this time.

  - CVE-2015-8779
    The catopen function contains several unbound stack
    allocations (stack overflows), causing it the crash the
    process (denial of service). No applications where this
    issue has a security impact are currently known.

The following fixed vulnerabilities currently lack CVE assignment :

  - Joseph Myers reported that an integer overflow in the
    strxfrm can lead to heap-based buffer overflow, possibly
    allowing arbitrary code execution. In addition, a
    fallback path in strxfrm uses an unbounded stack
    allocation (stack overflow), leading to a crash or
    erroneous application behavior.
  - Kostya Serebryany reported that the fnmatch function
    could skip over the terminating NUL character of a
    malformed pattern, causing an application calling
    fnmatch to crash (denial of service).

  - Joseph Myers reported that the IO_wstr_overflow
    function, internally used by wide-oriented character
    streams, suffered from an integer overflow, leading to a
    heap-based buffer overflow. On GNU/Linux systems,
    wide-oriented character streams are rarely used, and no
    affected applications are known.

  - Andreas Schwab reported a memory leak (memory allocation
    without a matching deallocation) while processing
    certain DNS answers in getaddrinfo, related to the
    _nss_dns_gethostbyname4_r function. This vulnerability
    could lead to a denial of service.

While it is only necessary to ensure that all processes are not using
the old eglibc anymore, it is recommended to reboot the machines after
applying the security upgrade."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=779587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=796105"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=798316"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=801691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=803927"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812441"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=812455"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1781"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-7547"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8776"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8779"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/eglibc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3480"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the eglibc packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 2.13-38+deb7u10."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/16");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/17");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"eglibc-source", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"glibc-doc", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc-bin", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc-dev-bin", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dbg", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev-i386", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i386", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i686", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-pic", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-prof", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-amd64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dbg", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-amd64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-i386", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mips64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mipsn32", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-ppc64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390x", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-sparc64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i386", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i686", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-loongson2f", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mips64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mipsn32", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-pic", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-ppc64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-prof", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390x", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-sparc64", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-xen", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dbg", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dev", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-pic", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-prof", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"locales", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"locales-all", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"multiarch-support", reference:"2.13-38+deb7u10")) flag++;
if (deb_check(release:"7.0", prefix:"nscd", reference:"2.13-38+deb7u10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
