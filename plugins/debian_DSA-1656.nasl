#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1656. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(34449);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-3639", "CVE-2008-3640", "CVE-2008-3641");
  script_osvdb_id(49130, 49131, 49132);
  script_xref(name:"DSA", value:"1656");

  script_name(english:"Debian DSA-1656-1 : cupsys - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in the Common UNIX
Printing System. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2008-3639
    It was discovered that insufficient bounds checking in
    the SGI image filter may lead to the execution of
    arbitrary code.

  - CVE-2008-3640
    It was discovered that an integer overflow in the
    Postscript conversion tool 'texttops' may lead to the
    execution of arbitrary code.

  - CVE-2008-3641
    It was discovered that insufficient bounds checking in
    the HPGL filter may lead to the execution of arbitrary
    code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-3641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1656"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cupsys package.

For the stable distribution (etch), these problems have been fixed in
version 1.2.7-4etch5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(119, 189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/10/21");
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
if (deb_check(release:"4.0", prefix:"cupsys", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-bsd", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-client", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-common", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-dbg", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2-dev", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-dev", reference:"1.2.7-4etch5")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-gnutls10", reference:"1.2.7-4etch5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
