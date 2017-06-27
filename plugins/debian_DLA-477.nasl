#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-477-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91197);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-7558", "CVE-2016-4347", "CVE-2016-4348");
  script_osvdb_id(132135, 137807, 137808);

  script_name(english:"Debian DLA-477-1 : librsvg security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"(Note CVE-2016-4347 is a duplicate of CVE-2015-7558)

Two DoS in librsvg 2.40.2 parsing SVGs with circular definitions were
found (they will produce stack exhaustion) by Gustavo Grieco.

The version in wheezy (2.36.1-2+deb7u1) is also vulnerable.

For Debian 7 'Wheezy', these problems have been fixed in version
2.36.1-2+deb7u2.

We recommend that you upgrade your librsvg packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/librsvg"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gir1.2-rsvg-2.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librsvg2-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/18");
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
if (deb_check(release:"7.0", prefix:"gir1.2-rsvg-2.0", reference:"2.36.1-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librsvg2-2", reference:"2.36.1-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librsvg2-bin", reference:"2.36.1-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librsvg2-common", reference:"2.36.1-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librsvg2-dbg", reference:"2.36.1-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librsvg2-dev", reference:"2.36.1-2+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"librsvg2-doc", reference:"2.36.1-2+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
