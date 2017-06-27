#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1292. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(25229);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2007-0242");
  script_bugtraq_id(23269);
  script_osvdb_id(34679);
  script_xref(name:"DSA", value:"1292");

  script_name(english:"Debian DSA-1292-1 : qt4-x11 - missing input validation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Andreas Nolden discovered a bug in the UTF8 decoding routines in
qt4-x11, a C++ GUI library framework, that could allow remote
attackers to conduct cross-site scripting (XSS) and directory
traversal attacks via long sequences that decode to dangerous
metacharacters."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=417391"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1292"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qt4-x11 package.

For the stable distribution (etch), this problem has been fixed in
version 4.2.1-2etch1.

For the testing and unstable distribution (lenny and sid,
respectively), this problem has been fixed in version 4.2.2-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt4-x11");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/05/16");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libqt4-core", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt4-debug", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt4-dev", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt4-gui", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt4-qt3support", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt4-sql", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt4-designer", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt4-dev-tools", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt4-doc", reference:"4.2.1-2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt4-qtconfig", reference:"4.2.1-2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
