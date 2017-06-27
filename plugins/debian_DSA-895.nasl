#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-895. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22761);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2013/05/18 00:19:43 $");

  script_cve_id("CVE-2005-3149");
  script_osvdb_id(19741);
  script_xref(name:"DSA", value:"895");

  script_name(english:"Debian DSA-895-1 : uim - programming error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Masanari Yamamoto discovered incorrect use of environment variables in
uim, a flexible input method collection and library, that could lead
to escalated privileges in setuid/setgid applications linked to
libuim. Affected in Debian is at least mlterm."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=331620"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-895"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libuim packages.

The old stable distribution (woody) does not contain uim packages.

For the stable distribution (sarge) this problem has been fixed in
version 0.4.6final1-3sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:uim");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libuim-dev", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libuim-nox-dev", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libuim0", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libuim0-dbg", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libuim0-nox", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"libuim0-nox-dbg", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-anthy", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-applet-gnome", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-canna", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-common", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-fep", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-gtk2.0", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-m17nlib", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-prime", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-skk", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-utils", reference:"0.4.6final1-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"uim-xim", reference:"0.4.6final1-3sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
