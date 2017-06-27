#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-773-4. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(96189);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/01/11 14:52:36 $");

  script_name(english:"Debian DLA-773-4 : python-crypto update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The previous security updates for python-crypto (DLA-773-1, DLA-773-2
& DLA-773-3) were not available on non-amd64 architectures.

This was due to the testsuite failing to exit gracefully when
'multiprocessing' based tests were not functioning or available, such
as on the Debian buildd network.

For Debian 7 'Wheezy', this issue has been fixed in python-crypto
version 2.6-4+deb7u7. There has been no change to the codepath
associated with the original CVE (2013-7459).

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/01/msg00010.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-crypto"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-crypto-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-crypto");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python3-crypto-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/03");
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
if (deb_check(release:"7.0", prefix:"python-crypto", reference:"2.6-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto-dbg", reference:"2.6-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"python-crypto-doc", reference:"2.6-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"python3-crypto", reference:"2.6-4+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"python3-crypto-dbg", reference:"2.6-4+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
