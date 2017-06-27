#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-91-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82236);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_name(english:"Debian DLA-91-2 : tomcat6 regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update fixes a 'NoSuchElementException' when an XML attribute has
an empty string as value.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/01/msg00009.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tomcat6"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.4-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libservlet2.5-java-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtomcat6-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-admin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-examples");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-extras");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tomcat6-user");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"libservlet2.4-java", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libservlet2.5-java-doc", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libtomcat6-java", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-admin", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-common", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-docs", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-examples", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-extras", reference:"6.0.41-2+squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"tomcat6-user", reference:"6.0.41-2+squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
