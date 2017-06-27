#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-676-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94255);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2016/10/26 14:35:57 $");

  script_name(english:"Debian DLA-676-1 : nspr security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Network Security Service (NSS) libraries uses environment
variables to configure lots of things, some of which refer to file
system locations. Others can be degrade the operation of NSS in
various ways, forcing compatibility modes and so on.

Previously, these environment variables were not ignored SUID
binaries. This version of NetScape Portable Runtime Library (NSPR)
introduce a new API, PR_GetEnVSecure, to address this.

Both NSPR and NSS need to be upgraded to address this problem.

For Debian 7 'Wheezy', these problems have been fixed in NSPR version
4.12-1+deb7u1.

We recommend that you upgrade your nspr packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00031.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nspr"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4-0d");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libnspr4-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/26");
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
if (deb_check(release:"7.0", prefix:"libnspr4", reference:"4.12-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4-0d", reference:"4.12-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4-dbg", reference:"4.12-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libnspr4-dev", reference:"4.12-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
