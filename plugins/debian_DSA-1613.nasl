#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1613. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(33552);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2007-2445", "CVE-2007-3476", "CVE-2007-3477", "CVE-2007-3996");
  script_bugtraq_id(24651, 25498);
  script_osvdb_id(36196, 36870, 37741, 42062);
  script_xref(name:"DSA", value:"1613");

  script_name(english:"Debian DSA-1613-1 : libgd2 - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been identified in libgd2, a library for
programmatic graphics creation and manipulation. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-2445
    Grayscale PNG files containing invalid tRNS chunk CRC
    values could cause a denial of service (crash), if a
    maliciously crafted image is loaded into an application
    using libgd.

  - CVE-2007-3476
    An array indexing error in libgd's GIF handling could
    induce a denial of service (crash with heap corruption)
    if exceptionally large color index values are supplied
    in a maliciously crafted GIF image file.

  - CVE-2007-3477
    The imagearc() and imagefilledarc() routines in libgd
    allow an attacker in control of the parameters used to
    specify the degrees of arc for those drawing functions
    to perform a denial of service attack (excessive CPU
    consumption).

  - CVE-2007-3996
    Multiple integer overflows exist in libgd's image
    resizing and creation routines; these weaknesses allow
    an attacker in control of the parameters passed to those
    routines to induce a crash or execute arbitrary code
    with the privileges of the user running an application
    or interpreter linked against libgd2."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=443456"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-2445"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3476"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3996"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1613"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libgd2 packages.

For the stable distribution (etch), these problems have been fixed in
version 2.0.33-5.2etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgd2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/07/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/07/23");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/15");
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
if (deb_check(release:"4.0", prefix:"libgd-tools", reference:"2.0.33-5.2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-noxpm", reference:"2.0.33-5.2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-noxpm-dev", reference:"2.0.33-5.2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-xpm", reference:"2.0.33-5.2etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgd2-xpm-dev", reference:"2.0.33-5.2etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
