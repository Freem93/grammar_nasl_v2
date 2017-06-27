#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-627. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16105);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1318");
  script_osvdb_id(12516);
  script_xref(name:"DSA", value:"627");

  script_name(english:"Debian DSA-627-1 : namazu2 - unsanitised input");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A cross-site scripting vulnerability has been discovered in namazu2, a
full text search engine. An attacker could prepare specially crafted
input that would not be sanitised by namazu2 and hence displayed
verbatim for the victim."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-627"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the namazu2 package.

For the stable distribution (woody) this problem has been fixed in
version 2.0.10-1woody3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:namazu2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/12/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libnmz3", reference:"2.0.10-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"libnmz3-dev", reference:"2.0.10-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"namazu2", reference:"2.0.10-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"namazu2-common", reference:"2.0.10-1woody3")) flag++;
if (deb_check(release:"3.0", prefix:"namazu2-index-tools", reference:"2.0.10-1woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
