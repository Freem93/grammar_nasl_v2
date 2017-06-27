#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-103. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14940);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/17 23:36:51 $");

  script_cve_id("CVE-2001-0886");
  script_xref(name:"DSA", value:"103");

  script_name(english:"Debian DSA-103-1 : glibc - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A buffer overflow has been found in the globbing code for glibc. This
is the code which is used to glob patterns for filenames and is
commonly used in applications like shells and FTP servers."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-103"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"This has been fixed in version 2.1.3-20 and we recommend that you
upgrade your libc package immediately."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:glibc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"glibc-doc", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"i18ndata", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-dbg", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-dev", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-pic", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6-prof", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-dbg", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-dev", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-pic", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libc6.1-prof", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"libnss1-compat", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"locales", reference:"2.1.3-20")) flag++;
if (deb_check(release:"2.2", prefix:"nscd", reference:"2.1.3-20")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
