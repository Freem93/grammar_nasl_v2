#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3012. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77418);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-5119");
  script_bugtraq_id(68983);
  script_osvdb_id(109188);
  script_xref(name:"DSA", value:"3012");

  script_name(english:"Debian DSA-3012-1 : eglibc - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tavis Ormandy discovered a heap-based buffer overflow in the
transliteration module loading code in eglibc, Debian's version of the
GNU C Library. As a result, an attacker who can supply a crafted
destination character set argument to iconv-related character
conversation functions could achieve arbitrary code execution.

This update removes support of loadable gconv transliteration modules.
Besides the security vulnerability, the module loading code had
functionality defects which prevented it from working for the intended
purpose."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/eglibc"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3012"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the eglibc packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2.13-38+deb7u4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:eglibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"eglibc-source", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"glibc-doc", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc-bin", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc-dev-bin", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dbg", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-dev-i386", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i386", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-i686", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-pic", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc0.1-prof", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-amd64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dbg", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-amd64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-i386", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mips64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-mipsn32", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-ppc64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-s390x", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-dev-sparc64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i386", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-i686", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-loongson2f", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mips64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-mipsn32", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-pic", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-ppc64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-prof", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-s390x", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-sparc64", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6-xen", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dbg", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-dev", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-pic", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libc6.1-prof", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"locales", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"locales-all", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"multiarch-support", reference:"2.13-38+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"nscd", reference:"2.13-38+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
