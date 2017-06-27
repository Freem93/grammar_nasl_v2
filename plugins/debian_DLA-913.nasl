#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-913-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99638);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/25 13:23:28 $");

  script_cve_id("CVE-2015-7559");
  script_osvdb_id(156066);

  script_name(english:"Debian DLA-913-1 : activemq security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that Apache ActiveMQ exposed a remote shutdown command in
the ActiveMQConnection class. An attacker could use this flaw to
achieve denial of service on a client.

For Debian 7 'Wheezy', these problems have been fixed in version
5.6.0+dfsg-1+deb7u3.

We recommend that you upgrade your activemq packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00033.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/activemq"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:activemq");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libactivemq-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libactivemq-java-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"activemq", reference:"5.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libactivemq-java", reference:"5.6.0+dfsg-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libactivemq-java-doc", reference:"5.6.0+dfsg-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
