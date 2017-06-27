#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-675-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(94293);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2017/02/13 20:45:09 $");

  script_cve_id("CVE-2013-7437", "CVE-2016-8694", "CVE-2016-8695", "CVE-2016-8696", "CVE-2016-8697", "CVE-2016-8698", "CVE-2016-8699", "CVE-2016-8700", "CVE-2016-8701", "CVE-2016-8702", "CVE-2016-8703");
  script_bugtraq_id(73395);
  script_osvdb_id(118082, 145801, 145802, 145803, 145804, 145805, 145806, 145807, 145808, 145809, 145810);

  script_name(english:"Debian DLA-675-1 : potrace security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in potrace.

CVE-2013-7437

Multiple integer overflows in potrace 1.11 allow remote attackers to
cause a denial of service (crash) via large dimensions in a BMP image,
which triggers a buffer overflow. This bug was reported by Murray
McAllister of the Red Hat Security Response Team.

CVE-2016-8694 CVE-2016-8695 CVE-2016-8696

Multiple NULL pointer dereferences in bm_readbody_bmp. This bug was
discovered by Agostino Sarubbo of Gentoo.

CVE-2016-8697

Division by zero in bm_new. This bug was discovered by Agostino
Sarubbo of Gentoo.

CVE-2016-8698 CVE-2016-8699 CVE-2016-8700 CVE-2016-8701 CVE-2016-8702
CVE-2016-8703

Multiple heap-based buffer overflows in bm_readbody_bmp. This bug was
discovered by Agostino Sarubbo of Gentoo.

For Debian 7 'Wheezy', these problems have been fixed in version
1.10-1+deb7u1.

We recommend that you upgrade your potrace packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/10/msg00034.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/potrace"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:X/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpotrace-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpotrace0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:potrace");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/10/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libpotrace-dev", reference:"1.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpotrace0", reference:"1.10-1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"potrace", reference:"1.10-1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
