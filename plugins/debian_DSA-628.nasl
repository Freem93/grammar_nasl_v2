#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-628. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16106);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/18 00:15:57 $");

  script_cve_id("CVE-2004-1025", "CVE-2004-1026");
  script_osvdb_id(10788, 12843);
  script_xref(name:"DSA", value:"628");

  script_name(english:"Debian DSA-628-1 : imlib2 - integer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Pavel Kankovsky discovered that several overflows found in the libXpm
library were also present in imlib and imlib2, imaging libraries for
X11. An attacker could create a carefully crafted image file in such a
way that it could cause an application linked with imlib or imlib2 to
execute arbitrary code when the file was opened by a victim. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2004-1025
    Multiple heap-based buffer overflows. No such code is
    present in imlib2.

  - CAN-2004-1026

    Multiple integer overflows in the imlib library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-628"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imlib2 packages.

For the stable distribution (woody) these problems have been fixed in
version 1.0.5-2woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imlib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/12");
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
if (deb_check(release:"3.0", prefix:"libimlib2", reference:"1.0.5-2woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libimlib2-dev", reference:"1.0.5-2woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
