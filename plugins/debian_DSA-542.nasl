#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-542. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15379);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2016/05/20 13:54:16 $");

  script_cve_id("CVE-2004-0691", "CVE-2004-0692", "CVE-2004-0693");
  script_osvdb_id(9026, 9035, 9036);
  script_xref(name:"DSA", value:"542");

  script_name(english:"Debian DSA-542-1 : qt - unsanitised input");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in recent versions of Qt, a
commonly used graphic widget set, used in KDE for example. The first
problem allows an attacker to execute arbitrary code, while the other
two only seem to pose a denial of service danger. The Common
Vulnerabilities and Exposures project identifies the following
vulnerabilities :

  - CAN-2004-0691 :
    Chris Evans has discovered a heap-based overflow when
    handling 8-bit RLE encoded BMP files.

  - CAN-2004-0692 :

    Marcus Meissner has discovered a crash condition in the
    XPM handling code, which is not yet fixed in Qt 3.3.

  - CAN-2004-0693 :

    Marcus Meissner has discovered a crash condition in the
    GIF handling code, which is not yet fixed in Qt 3.3."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=267092"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-542"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qt packages.

For the stable distribution (woody) these problems have been fixed in
version 3.0.3-20020329-1woody2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt-copy");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/08/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/08/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libqt3", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-dev", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-mt", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-mt-dev", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-mt-mysql", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-mt-odbc", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-mysql", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqt3-odbc", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"libqxt0", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"qt3-doc", reference:"3.0.3-20020329-1woody2")) flag++;
if (deb_check(release:"3.0", prefix:"qt3-tools", reference:"3.0.3-20020329-1woody2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
