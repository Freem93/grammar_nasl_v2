#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-323-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86226);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_name(english:"Debian DLA-323-1 : fuseiso security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The following two issues have recently been fixed in Debian LTS
(squeeze) for the fuseiso package.

Issue 1

An integer overflow, leading to a heap-based buffer overflow flaw was
found in the way FuseISO, a FUSE module to mount ISO filesystem
images, performed reading of certain ZF blocks of particular inodes. A
remote attacker could provide a specially crafted ISO file that, when
mounted via the fuseiso tool would lead to fuseiso binary crash.

This issue was discovered by Florian Weimer of Red Hat
Product Security Team.

The issue got resolve by bailing out before ZF blocks that
exceed the supported block size of 2^17 are to be read.

Issue 2

A stack-based buffer overflow flaw was found in the way FuseISO, a
FUSE module to mount ISO filesystem images, performed expanding of
directory portions for absolute path filename entries. A remote
attacker could provide a specially crafted ISO file that, when mounted
via fuseiso tool would lead to fuseiso binary crash or, potentially,
arbitrary code execution with the privileges of the user running the
fuseiso executable.

This issue was discovered by Florian Weimer of Red Hat
Product Security Team.

The issue got resolved by checking the resulting length of
an absolute path name and by bailing out if the platform's
PATH_MAX value gets exceeded.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/10/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/fuseiso"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected fuseiso package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:fuseiso");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"fuseiso", reference:"20070708-2+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
