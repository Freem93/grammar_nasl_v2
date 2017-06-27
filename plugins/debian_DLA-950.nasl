#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-950-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100360);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/05/25 13:29:26 $");

  script_cve_id("CVE-2017-6891");
  script_osvdb_id(157902);

  script_name(english:"Debian DLA-950-1 : libtasn1-3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Secunia Research has discovered multiple vulnerabilities in GnuTLS
libtasn1, which can be exploited by malicious people to compromise a
vulnerable system.

Two errors in the 'asn1_find_node()' function (lib/parser_aux.c) can
be exploited to cause a stacked-based buffer overflow.

Successful exploitation of the vulnerabilities allows execution of
arbitrary code but requires tricking a user into processing a
specially crafted assignments file by e.g. asn1Coding utility.

For Debian 7 'Wheezy', this problem has been fixed in version
2.13-2+deb7u4.

We recommend that you upgrade your libtasn1-3 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libtasn1-3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-3-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-3-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtasn1-3-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/24");
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
if (deb_check(release:"7.0", prefix:"libtasn1-3", reference:"2.13-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtasn1-3-bin", reference:"2.13-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtasn1-3-dbg", reference:"2.13-2+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtasn1-3-dev", reference:"2.13-2+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
