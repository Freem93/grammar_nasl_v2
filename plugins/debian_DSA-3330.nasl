#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3330. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85353);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/10/10 14:05:03 $");

  script_cve_id("CVE-2014-3576");
  script_xref(name:"DSA", value:"3330");

  script_name(english:"Debian DSA-3330-1 : activemq - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Apache ActiveMQ message broker is
susceptible to denial of service through an undocumented, remote
shutdown command."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3612"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/activemq"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/activemq"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3330"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the activemq packages.

For the oldstable distribution (wheezy), this problem has been fixed
in version 5.6.0+dfsg-1+deb7u1. This update also fixes CVE-2014-3612
and CVE-2014-3600.

For the stable distribution (jessie), this problem has been fixed in
version 5.6.0+dfsg1-4+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:activemq");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/08/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"activemq", reference:"5.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libactivemq-java", reference:"5.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libactivemq-java-doc", reference:"5.6.0+dfsg-1+deb7u1")) flag++;
if (deb_check(release:"8.0", prefix:"activemq", reference:"5.6.0+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libactivemq-java", reference:"5.6.0+dfsg1-4+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libactivemq-java-doc", reference:"5.6.0+dfsg1-4+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
