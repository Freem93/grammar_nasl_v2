#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3129. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(80573);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/02/16 15:48:48 $");

  script_cve_id("CVE-2013-6435", "CVE-2014-8118");
  script_bugtraq_id(71558, 71588);
  script_xref(name:"DSA", value:"3129");

  script_name(english:"Debian DSA-3129-1 : rpm - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in the RPM package manager.

  - CVE-2013-6435
    Florian Weimer discovered a race condition in package
    signature validation.

  - CVE-2014-8118
    Florian Weimer discovered an integer overflow in parsing
    CPIO headers which might result in the execution of
    arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-8118"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/rpm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3129"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the rpm packages.

For the stable distribution (wheezy), these problems have been fixed
in version 4.10.0-5+deb7u2.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 4.11.3-1.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"librpm-dbg", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librpm-dev", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librpm3", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librpmbuild3", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librpmio3", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librpmsign1", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-rpm", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"rpm", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"rpm-common", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"rpm-i18n", reference:"4.10.0-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"rpm2cpio", reference:"4.10.0-5+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
