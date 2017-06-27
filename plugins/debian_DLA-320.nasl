#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-320-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86212);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_name(english:"Debian DLA-320-1 : libemail-address-perl security update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Pali Roh&aacute;r discovered [1] a possible DoS attack in any software
which uses the Email::Address Perl module for parsing string input to
a list of email addresses.

By default Email::Address module, version v1.907 (and all before)
tries to understand nestable comments in an input string with depth
level 2.

With specially crafted inputs, parsing nestable comments can become
too slow and can cause high CPU load, freeze the application and end
in Denial of Service.

Because input strings for Email::Address module come from external
sources (e.g. from email sent by an attacker) it is a security problem
impacting on all software applications which parse email messages
using the Email::Address Perl module.

With this upload of libemail-address-perl, the default value of
nestable comments has been set to depth level 1 (as proposed by
upstream). Please note that this is not proper a fix, just a
workaround for pathological inputs with nestable comments.

[1] http://www.openwall.com/lists/oss-security/2015/09/27/1

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openwall.com/lists/oss-security/2015/09/27/1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libemail-address-perl"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected libemail-address-perl package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libemail-address-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/10/01");
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
if (deb_check(release:"6.0", prefix:"libemail-address-perl", reference:"1.889-2+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
