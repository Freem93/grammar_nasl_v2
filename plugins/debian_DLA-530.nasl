#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-530-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91836);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/06/27 14:51:42 $");

  script_name(english:"Debian DLA-530-1 : java-common security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"As previously announced [1][2], the default Java implementation has
been switched from OpenJDK 6 to OpenJDK 7. We strongly recommend to
remove the unsupported OpenJDK 6 packages which will receive no
further security updates.

[1] https://lists.debian.org/debian-lts-announce/2016/05/msg00007.html
[2] https://www.debian.org/News/2016/20160425

For Debian 7 'Wheezy', these problems have been fixed in version
0.47+deb7u2.

We recommend that you upgrade your java-common packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00007.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/06/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/java-common"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.debian.org/News/2016/20160425"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:default-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:default-jdk-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:default-jre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:default-jre-headless");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gcj-native-helper");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:java-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/27");
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
if (deb_check(release:"7.0", prefix:"default-jdk", reference:"0.47+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"default-jdk-doc", reference:"0.47+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"default-jre", reference:"0.47+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"default-jre-headless", reference:"0.47+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"gcj-native-helper", reference:"0.47+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"java-common", reference:"0.47+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
