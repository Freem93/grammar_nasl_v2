#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-199-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82785);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2013-7439");
  script_bugtraq_id(73962);
  script_osvdb_id(120543);

  script_name(english:"Debian DLA-199-1 : libx11 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Abhishek Arya discovered a buffer overflow in the MakeBigReq macro
provided by libx11, which could result in denial of service or the
execution of arbitrary code.

Several other xorg packages (e.g. libxrender) will be recompiled
against the fixed package after the release of this update. For
detailed information on the status of recompiled packages please refer
to the Debian Security Tracker at
https://security-tracker.debian.org/tracker/CVE-2013-7439

For the oldstable distribution (squeeze), this problem has been fixed
in version 2:1.3.3-4+squeeze2.

For the stable distribution (wheezy), this problem has been fixed in
version 2:1.5.0-1+deb7u2.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libx11"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-7439"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-6-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-data");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libx11-xcb1-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/15");
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
if (deb_check(release:"6.0", prefix:"libx11-6", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-6-dbg", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-6-udeb", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-data", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-dev", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-xcb-dev", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-xcb1", reference:"2:1.3.3-4+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libx11-xcb1-dbg", reference:"2:1.3.3-4+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
