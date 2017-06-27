#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3555. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(90687);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2011-5326", "CVE-2014-9771", "CVE-2016-3993", "CVE-2016-3994", "CVE-2016-4024");
  script_osvdb_id(122453, 136663, 136950, 137135, 137991);
  script_xref(name:"DSA", value:"3555");

  script_name(english:"Debian DSA-3555-1 : imlib2 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in imlib2, an image
manipulation library.

  - CVE-2011-5326
    Kevin Ryde discovered that attempting to draw a 2x1 radi
    ellipse results in a floating point exception.

  - CVE-2014-9771
    It was discovered that an integer overflow could lead to
    invalid memory reads and unreasonably large memory
    allocations.

  - CVE-2016-3993
    Yuriy M. Kaminskiy discovered that drawing using
    coordinates from an untrusted source could lead to an
    out-of-bound memory read, which in turn could result in
    an application crash.

  - CVE-2016-3994
    Jakub Wilk discovered that a malformed image could lead
    to an out-of-bound read in the GIF loader, which may
    result in an application crash or information leak.

  - CVE-2016-4024
    Yuriy M. Kaminskiy discovered an integer overflow that
    could lead to an insufficient heap allocation and
    out-of-bound memory write."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=639414"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=785369"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=819818"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=820206"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=821732"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-5326"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3993"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-3994"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-4024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/imlib2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/imlib2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3555"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the imlib2 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.4.5-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed
in version 1.4.6-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imlib2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libimlib2", reference:"1.4.5-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libimlib2-dev", reference:"1.4.5-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libimlib2", reference:"1.4.6-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libimlib2-dev", reference:"1.4.6-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
