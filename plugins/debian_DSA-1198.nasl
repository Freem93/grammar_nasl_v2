#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1198. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22907);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2013/05/17 23:41:26 $");

  script_cve_id("CVE-2006-4980");
  script_osvdb_id(29366);
  script_xref(name:"DSA", value:"1198");

  script_name(english:"Debian DSA-1198-1 : python2.3 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Benjamin C. Wiley Sittler discovered that the repr() of the Python
interpreter allocates insufficient memory when parsing UCS-4 Unicode
strings, which might lead to execution of arbitrary code through a
buffer overflow."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=391589"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1198"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Python 2.3 packages.

For the stable distribution (sarge) this problem has been fixed in
version 2.3.5-3sarge2. Due to build problems this update lacks fixed
packages for the Alpha and Sparc architectures. Once they are sorted
out, fixed binaries will be released."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python2.3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/08/16");
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
if (deb_check(release:"3.1", prefix:"idle-python2.3", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-dev", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-doc", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-examples", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-gdbm", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-mpz", reference:"2.3.5-3sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-tk", reference:"2.3.5-3sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
