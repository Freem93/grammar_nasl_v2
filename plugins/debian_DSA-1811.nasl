#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1811. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38992);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/08/20 15:05:35 $");

  script_cve_id("CVE-2009-0949");
  script_osvdb_id(55002);
  script_xref(name:"DSA", value:"1811");

  script_name(english:"Debian DSA-1811-1 : cups, cupsys - null ptr dereference");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Anibal Sacco discovered that cups, a general printing system for UNIX
systems, suffers from NULL pointer dereference because of its handling
of two consecutive IPP packets with certain tag attributes that are
treated as IPP_TAG_UNSUPPORTED tags. This allows unauthenticated
attackers to perform denial of service attacks by crashing the cups
daemon."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1811"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups/cupsys packages.

For the oldstable distribution (etch), this problem has been fixed in
version 1.2.7-4+etch8 of cupsys.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny6 of cups."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cupsys");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cupsys", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-bsd", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-client", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-common", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"cupsys-dbg", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsimage2-dev", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-dev", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"4.0", prefix:"libcupsys2-gnutls10", reference:"1.2.7-4+etch8")) flag++;
if (deb_check(release:"5.0", prefix:"cups", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cups-bsd", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cups-client", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cups-common", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cups-dbg", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-bsd", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-client", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-common", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-dbg", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libcups2", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libcups2-dev", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsimage2", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsimage2-dev", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsys2", reference:"1.3.8-1+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsys2-dev", reference:"1.3.8-1+lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
