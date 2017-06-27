#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1625. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33774);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-0053", "CVE-2008-1373", "CVE-2008-1722");
  script_osvdb_id(44160, 44398);
  script_xref(name:"DSA", value:"1625");

  script_name(english:"Debian DSA-1625-1 : cupsys - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Common Unix
Printing System (CUPS). The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-0053
    Buffer overflows in the HP-GL input filter allowed to
    possibly run arbitrary code through crafted HP-GL files.

  - CVE-2008-1373
    Buffer overflow in the GIF filter allowed to possibly
    run arbitrary code through crafted GIF files.

  - CVE-2008-1722
    Integer overflows in the PNG filter allowed to possibly
    run arbitrary code through crafted PNG files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=476305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-0053"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1625"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cupsys package.

For the stable distribution (etch), these problems have been fixed in
version 1.2.7-4etch4 of package cupsys."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(20, 119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cupsys", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-bsd", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-client", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-common", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-dbg", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2-dev", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-dev", reference:"1.2.7-4etch4")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-gnutls10", reference:"1.2.7-4etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
