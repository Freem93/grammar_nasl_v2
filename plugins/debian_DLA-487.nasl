#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-487-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91323);
  script_version("$Revision: 2.1 $");
  script_cvs_date("$Date: 2016/05/26 16:22:51 $");

  script_name(english:"Debian DLA-487-1 : debian-security-support - Long term security support update");
  script_summary(english:"Checks dpkg output for the updated package.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Debian Long Term Support (LTS) Team is unable to continue
supporting different packages in the extended life cycle of Wheezy
LTS. The debian-security-support package provides the
check-support-status tool that helps to warn the administrator about
installed packages whose security support is limited or has to
prematurely end.

debian-security-support version 2016.05.24~deb7u1 updates the list of
packages with restricted support in Wheezy LTS, adding the following :

Source Package Last supported version EOL date Additional information

  - libv8 3.8.9.20-2 2016-02-06
    https://lists.debian.org/debian-lts/2015/08/msg00035.htm
    l

  - mediawiki 1:1.19.20+dfsg-0+deb7u3 2016-04-26
    https://www.debian.org/releases/jessie/amd64/release-not
    es/ch-information.html#mediawiki-security

  - sogo 1.3.16-1 2016-05-19
    https://lists.debian.org/debian-lts/2016/05/msg00197.htm
    l

  - vlc 2.0.3-5+deb7u2 2016-02-06
    https://lists.debian.org/debian-lts/2015/11/msg00049.htm
    l

If you rely on those packages on a system running Debian 7 'Wheezy',
we recommend you to upgrade to Debian 8 'Jessie', the current stable
release. Note however that the mediawiki support has also ended in
Jessie. 

We recommend you to install the debian-security-support package to
verify the support status of the packages installed on the system.

More information about Debian LTS can be found at:
https://wiki.debian.org/LTS

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00042.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts/2015/08/msg00035.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts/2015/11/msg00049.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts/2016/05/msg00197.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/debian-security-support"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS"
  );
  # https://www.debian.org/releases/jessie/amd64/release-notes/ch-information.html#mediawiki-security
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bda4d120"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected debian-security-support package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:debian-security-support");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/26");
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
if (deb_check(release:"7.0", prefix:"debian-security-support", reference:"2016.05.24~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
