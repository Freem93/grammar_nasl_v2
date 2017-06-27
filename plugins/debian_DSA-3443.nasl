#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3443. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(87899);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2015-8472", "CVE-2015-8540");
  script_osvdb_id(130175, 131598);
  script_xref(name:"DSA", value:"3443");

  script_name(english:"Debian DSA-3443-1 : libpng - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the libpng PNG
library. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2015-8472
    It was discovered that the original fix for
    CVE-2015-8126 was incomplete and did not detect a
    potential overrun by applications using png_set_PLTE
    directly. A remote attacker can take advantage of this
    flaw to cause a denial of service (application crash).

  - CVE-2015-8540
    Xiao Qixue and Chen Yu discovered a flaw in the
    png_check_keyword function. A remote attacker can
    potentially take advantage of this flaw to cause a
    denial of service (application crash)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=807112"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=807694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libpng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libpng"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3443"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libpng packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.2.49-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed
in version 1.2.50-2+deb8u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/14");
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
if (deb_check(release:"7.0", prefix:"libpng12-0", reference:"1.2.49-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpng12-0-udeb", reference:"1.2.49-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpng12-dev", reference:"1.2.49-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libpng3", reference:"1.2.49-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpng12-0", reference:"1.2.50-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpng12-0-udeb", reference:"1.2.50-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpng12-dev", reference:"1.2.50-2+deb8u2")) flag++;
if (deb_check(release:"8.0", prefix:"libpng3", reference:"1.2.50-2+deb8u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
