#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-546-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91979);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2016/07/15 13:34:30 $");

  script_name(english:"Debian DLA-546-2 : clamav version update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"DLA 546-1 was incorrectly released before updated clamav packages were
available and there were subsequent issues with the acceptance of the
package (which have since been corrected). Updates are now available
for all supported LTS architectures.

We recommend that you upgrade your clamav packages.

Upstream published version 0.99.2. This update updates wheezy-lts to
the latest upstream release in line with the approach used for other
Debian releases.

The changes are not strictly required for operation, but users of the
previous version in Wheezy may not be able to make use of all current
virus signatures and might get warnings.

For Debian 7 'Wheezy', this has been addressed in version
0.99.2+dfsg-0+deb7u2.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/07/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/clamav"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav7");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/07/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/07/08");
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
if (deb_check(release:"7.0", prefix:"clamav", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-base", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-daemon", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-dbg", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-docs", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-freshclam", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-milter", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"clamav-testfiles", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libclamav-dev", reference:"0.99.2+dfsg-0+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libclamav7", reference:"0.99.2+dfsg-0+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
