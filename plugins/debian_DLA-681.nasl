#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-681-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94295);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/10/27 13:13:07 $");

  script_name(english:"Debian DLA-681-1 : tzdata new upstream version");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"This update includes the changes in tzdata up to 2016h. Notable
changes are :

  - Asia/Gaza and Asia/Hebron (DST ending on 2016-10-29 at
    01:00, not 2016-10-21 at 00:00).

  - Europe/Istanbul switch from EET/EEST (+02/+03) to
    permanent +03 on 2016-09-07. While the time zone has
    changed, the divergence from EET/EEST will happen on
    2016-10-30.

  - Turkey switched from EET/EEST (+02/+03) to permanent
    +03, effective 2016-09-07.

  - New leap second 2016-12-31 23:59:60 UTC as per IERS
    Bulletin C 52.

For Debian 7 'Wheezy', these problems have been fixed in version
2016h-0+deb7u1.

We recommend that you upgrade your tzdata packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00036.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tzdata"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected tzdata, and tzdata-java packages."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tzdata");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:tzdata-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
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
if (deb_check(release:"7.0", prefix:"tzdata", reference:"2016h-0+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"tzdata-java", reference:"2016h-0+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
