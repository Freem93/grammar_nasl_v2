#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-139-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82122);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-0235");
  script_bugtraq_id(72325);
  script_osvdb_id(117579);

  script_name(english:"Debian DLA-139-1 : eglibc security update (GHOST)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been fixed in eglibc, Debian's version of the GNU
C library :

CVE-2015-0235

Qualys discovered that the gethostbyname and gethostbyname2 functions
were subject to a buffer overflow if provided with a crafted IP
address argument. This could be used by an attacker to execute
arbitrary code in processes which called the affected functions.

The original glibc bug was reported by Peter Klotz.

We recommend that you upgrade your eglibc packages.

The other three CVEs fixed in Debian wheezy via DSA 3142-1 have
already been fixed in squeeze LTS via DLA DLA 97-1.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/01/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/eglibc"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Exim GHOST (glibc gethostbyname) Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"in_the_news", value:"true");
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
if (deb_check(release:"6.0", prefix:"eglibc-source", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"glibc-doc", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc-bin", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc-dev-bin", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-amd64", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dbg", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-amd64", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-dev-i386", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i386", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-i686", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-pic", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-prof", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-udeb", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libc6-xen", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-dns-udeb", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libnss-files-udeb", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"locales", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"locales-all", reference:"2.11.3-4+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"nscd", reference:"2.11.3-4+deb6u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
