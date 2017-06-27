#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-927-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99738);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2017-5661");
  script_osvdb_id(155708);

  script_name(english:"Debian DLA-927-1 : fop security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"In Apache FOP before 2.2, files lying on the filesystem of the server
which uses FOP can be revealed to arbitrary users who send maliciously
formed SVG files. The file types that can be shown depend on the user
context in which the exploitable application is running. If the user
is root a full compromise of the server - including confidential or
sensitive files - would be possible. XXE can also be used to attack
the availability of the server via denial of service as the references
within a xml document can trivially trigger an amplification attack.

For Debian 7 'Wheezy', these problems have been fixed in version
1:1.0.dfsg2-6+deb7u1.

We recommend that you upgrade your fop packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00046.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/fop"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected fop, fop-doc, and libfop-java packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:N/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fop");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fop-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libfop-java");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
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
if (deb_check(release:"7.0", prefix:"fop", reference:"1:1.0.dfsg2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"fop-doc", reference:"1:1.0.dfsg2-6+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libfop-java", reference:"1:1.0.dfsg2-6+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
