#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-162-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82146);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2015-1572");
  script_bugtraq_id(72709);
  script_osvdb_id(118193);

  script_name(english:"Debian DLA-162-1 : e2fsprogs security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jose Duart of the Google Security Team discovered a buffer overflow in
in e2fsprogs, a set of utilities for the ext2, ext3, and ext4 file
systems. This issue can possibly lead to arbitrary code execution if a
malicious device is plugged in, the system is configured to
automatically mount it, and the mounting process chooses to run fsck
on the device's malicious filesystem.

CVE-2015-1572

Incomplete fix for CVE-2015-0247.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/e2fsprogs"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:comerr-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsck-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fslibs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fslibs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fslibs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:e2fsprogs-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcomerr2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcomerr2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libss2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libss2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ss-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"comerr-dev", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fsck-static", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fslibs", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fslibs-dbg", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fslibs-dev", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fsprogs", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fsprogs-dbg", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"e2fsprogs-udeb", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libcomerr2", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libcomerr2-dbg", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libss2", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libss2-dbg", reference:"1.41.12-4+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"ss-dev", reference:"1.41.12-4+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
