#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3142. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(81029);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2012-6656", "CVE-2014-6040", "CVE-2014-7817", "CVE-2015-0235");
  script_bugtraq_id(69472, 71216, 72325);
  script_osvdb_id(117579);
  script_xref(name:"CERT", value:"967332");
  script_xref(name:"DSA", value:"3142");

  script_name(english:"Debian DSA-3142-1 : eglibc - security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in eglibc, Debian's version of
the GNU C library :

  - CVE-2015-0235
    Qualys discovered that the gethostbyname and
    gethostbyname2 functions were subject to a buffer
    overflow if provided with a crafted IP address argument.
    This could be used by an attacker to execute arbitrary
    code in processes which called the affected functions.

  The original glibc bug was reported by Peter Klotz.

  - CVE-2014-7817
    Tim Waugh of Red Hat discovered that the WRDE_NOCMD
    option of the wordexp function did not suppress command
    execution in all cases. This allows a context-dependent
    attacker to execute shell commands.

  - CVE-2012-6656 CVE-2014-6040
    The charset conversion code for certain IBM multi-byte
    code pages could perform an out-of-bounds array access,
    causing the process to crash. In some scenarios, this
    allows a remote attacker to cause a persistent denial of
    service."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-7817"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-6656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-6040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-0235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3142"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the eglibc packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.13-38+deb7u7.

For the upcoming stable distribution (jessie) and the unstable
distribution (sid), the CVE-2015-0235 issue has been fixed in version
2.18-1 of the glibc package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/28");
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
if (deb_check(release:"7.0", prefix:"eglibc", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc-bin", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc-dev-bin", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev-i386", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i386", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i686", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-pic", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-prof", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-amd64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-amd64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-i386", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mips64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mipsn32", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-ppc64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390x", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-sparc64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i386", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i686", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-loongson2f", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mips64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mipsn32", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-pic", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-ppc64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-prof", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390x", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-sparc64", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-xen", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dev", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-pic", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-prof", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"locales", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"locales-all", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"multiarch-support", reference:"2.13-38+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"nscd", reference:"2.13-38+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
