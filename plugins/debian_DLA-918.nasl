#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-918-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99692);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/01 13:40:21 $");

  script_cve_id("CVE-2017-8105");
  script_osvdb_id(156267);

  script_name(english:"Debian DLA-918-1 : freetype security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was found that an out of bounds write caused by a heap-based buffer
overflow could be triggered in freetype via a crafted font.

This update also reverts the fix for CVE-2016-10328, as it was
determined that freetype 2.4.9 is not affected by that issue.

For Debian 7 'Wheezy', these problems have been fixed in version
2.4.9-1.1+deb7u6.

We recommend that you upgrade your freetype packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/freetype"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:freetype2-demos");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreetype6");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreetype6-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfreetype6-udeb");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/27");
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
if (deb_check(release:"7.0", prefix:"freetype2-demos", reference:"2.4.9-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libfreetype6", reference:"2.4.9-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libfreetype6-dev", reference:"2.4.9-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libfreetype6-udeb", reference:"2.4.9-1.1+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
