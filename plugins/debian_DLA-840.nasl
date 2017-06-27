#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-840-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97437);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/06 14:38:26 $");

  script_cve_id("CVE-2017-5834", "CVE-2017-5835");
  script_osvdb_id(151271, 151272);

  script_name(english:"Debian DLA-840-1 : libplist security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in libplist, a library for
reading and writing the Apple binary and XML property lists format. A
maliciously crafted plist file could cause an application to crash by
triggering a heap-based buffer overflow and memory allocation error in
the plist_from_bin function.

For Debian 7 'Wheezy', these problems have been fixed in version
1.8-1+deb7u2.

We recommend that you upgrade your libplist packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/02/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libplist"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist++1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libplist1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-plist");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/02/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/01");
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
if (deb_check(release:"7.0", prefix:"libplist++-dev", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libplist++1", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-dbg", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-dev", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-doc", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-utils", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libplist1", reference:"1.8-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"python-plist", reference:"1.8-1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
