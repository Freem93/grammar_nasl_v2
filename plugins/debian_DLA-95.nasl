#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-95-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82240);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2013-6497", "CVE-2014-9050");
  script_bugtraq_id(71178, 71242);
  script_osvdb_id(115012);

  script_name(english:"Debian DLA-95-1 : clamav security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two bugs were discovered in clamav and are fixed by this release.

One issue is in clamscan, the command line anti-virus scanner included
in the package, which could lead to crashes when scanning certain
files. (CVE-2013-6497)

The second issue is in libclamav which caused a heap buffer overflow
when scanning a specially crafted y0da Crypter obfuscated PE file.
(CVE-2014-9050) 

If you use clamav, we highly recommend that you upgrade to this
version.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/12/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/clamav"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-daemon");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-freshclam");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-milter");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:clamav-testfiles");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libclamav6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/12/02");
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
if (deb_check(release:"6.0", prefix:"clamav", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-base", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-daemon", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-dbg", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-docs", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-freshclam", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-milter", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"clamav-testfiles", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libclamav-dev", reference:"0.98.1+dfsg-1+deb6u4")) flag++;
if (deb_check(release:"6.0", prefix:"libclamav6", reference:"0.98.1+dfsg-1+deb6u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
