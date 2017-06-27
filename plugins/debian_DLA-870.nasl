#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-870-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97965);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2017-6435", "CVE-2017-6436", "CVE-2017-6439");
  script_osvdb_id(153921, 153925);

  script_name(english:"Debian DLA-870-1 : libplist security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"More vulnerabilities were discovered in libplist, a library for
reading and writing the Apple binary and XML property lists format. A
maliciously crafted plist file could cause a denial of service
(application crash) by triggering a heap-based buffer overflow or
memory allocation error in the parse_string_node function.

For Debian 7 'Wheezy', these problems have been fixed in version
1.8-1+deb7u3.

We recommend that you upgrade your libplist packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00028.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libplist"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:R/S:U/C:N/I:N/A:H");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
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
if (deb_check(release:"7.0", prefix:"libplist++-dev", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplist++1", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-dbg", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-dev", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-doc", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplist-utils", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"libplist1", reference:"1.8-1+deb7u3")) flag++;
if (deb_check(release:"7.0", prefix:"python-plist", reference:"1.8-1+deb7u3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
