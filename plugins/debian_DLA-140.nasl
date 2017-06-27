#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-140-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82123);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/08/22 14:13:37 $");

  script_cve_id("CVE-2012-0060", "CVE-2012-0061", "CVE-2012-0815", "CVE-2013-6435", "CVE-2014-8118");
  script_bugtraq_id(52865, 71558, 71588);
  script_osvdb_id(81009, 81010, 81011, 115601, 115602);

  script_name(english:"Debian DLA-140-1 : rpm security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been fixed in rpm :

CVE-2014-8118

Fix integer overflow which allowed remote attackers to execute
arbitrary code.

CVE-2013-6435

Prevent remote attackers from executing arbitrary code via crafted RPM
files.

CVE-2012-0815

Fix denial of service and possible code execution via negative value
in region offset in crafted RPM files.

CVE-2012-0060 and CVE-2012-0061

Prevent denial of service (crash) and possibly execute arbitrary code
execution via an invalid region tag in RPM files.

We recommend that you upgrade your rpm packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/01/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/rpm"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librpm-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librpm-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librpm1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librpmbuild1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:librpmio1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lsb-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rpm");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rpm-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rpm-i18n");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:rpm2cpio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"librpm-dbg", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"librpm-dev", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"librpm1", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"librpmbuild1", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"librpmio1", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"lsb-rpm", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-rpm", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rpm", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rpm-common", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rpm-i18n", reference:"4.8.1-6+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"rpm2cpio", reference:"4.8.1-6+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
