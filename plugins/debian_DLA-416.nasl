#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-416-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88764);
  script_version("$Revision: 2.19 $");
  script_cvs_date("$Date: 2017/01/27 23:31:26 $");

  script_cve_id("CVE-2015-7547");
  script_osvdb_id(134584);
  script_xref(name:"TRA", value:"TRA-2017-08");
  script_xref(name:"IAVA", value:"2016-A-0053");

  script_name(english:"Debian DLA-416-1 : eglibc security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in the Debian GNU C Library,
eglibc :

CVE-2015-7547 The Google Security Team and Red Hat discovered that the
glibc host name resolver function, getaddrinfo, when processing
AF_UNSPEC queries (for dual A/AAAA lookups), could mismange its
internal buffers, leading to a stack-based buffer overflow and
arbitrary code execution. This vulnerability affects most applications
which perform host name resolution using getaddrinfo, including system
services.

The following fixed vulnerabilities currently lack CVE assignment :

Andreas Schwab reported a memory leak (memory allocation without a
matching deallocation) while processing certain DNS answers in
getaddrinfo, related to the _nss_dns_gethostbyname4_r function. This
vulnerability could lead to a denial of service.

For Debian 6 'Squeeze', these issues have been fixed in eglibc version
eglibc_2.11.3-4+deb6u11. In addition this version corrects the fix for
CVE-2014-9761 in Squeeze, which have wrongly marked a few symbols as
public instead of private.

While it is only necessary to ensure that all processes are not using
the old eglibc anymore, it is recommended to reboot the machines after
applying the security upgrade.

We recommend you to upgrade your eglibc packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/eglibc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.tenable.com/security/research/tra-2017-08"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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
if (deb_check(release:"6.0", prefix:"eglibc-source", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"glibc-doc", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc-bin", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc-dev-bin", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-amd64", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dbg", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-amd64", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-i386", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i386", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i686", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-pic", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-prof", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-udeb", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-xen", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-dns-udeb", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-files-udeb", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"locales", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"locales-all", reference:"2.11.3-4+deb6u11")) flag++;
if (deb_check(release:"6.0", prefix:"nscd", reference:"2.11.3-4+deb6u11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
