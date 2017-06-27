#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-437-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88998);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/02/29 14:53:56 $");

  script_name(english:"Debian DLA-437-1 : clamav version update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Upstream published version 0.99. This update updates sqeeze-lts to the
latest upstream release in line with the approach used for other
Debian releases.

The changes are not strictly required for operation, but users of the
previous version in Squeeze may not be able to make use of all current
virus signatures and might get warnings.

Due to a change in soname included with this release, libclamav has
been updated to libclamav7. This requires updates to external users of
libclamav. For python-clamav, klamav, and libclamunrar, these changes
are, or will be shortly, available.

Unfortunately, for dansguardian, it was released for squeeze with
latent issues that preclude rebuilding the package. If you are using
dansguardian, do not attempt to upgrade to the new clamav.

Otherwise, if you use clamav, we strongly recommend that you upgrade
to this version.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/02/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/clamav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/29");
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
if (deb_check(release:"6.0", prefix:"clamav", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-base", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-daemon", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-dbg", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-docs", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-freshclam", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-milter", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-testfiles", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libclamav-dev", reference:"0.99+dfsg-0+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libclamav6", reference:"0.99+dfsg-0+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
