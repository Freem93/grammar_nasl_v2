#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-184-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82301);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-8484", "CVE-2014-8485", "CVE-2014-8501", "CVE-2014-8502", "CVE-2014-8503", "CVE-2014-8504", "CVE-2014-8737", "CVE-2014-8738");
  script_bugtraq_id(70714, 70741, 70761, 70866, 70868, 70869, 70908, 71083);
  script_osvdb_id(113682, 113735, 113825, 113828, 114037, 114039, 114129, 114209);

  script_name(english:"Debian DLA-184-1 : binutils security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been found in binutils, a toolbox for
binary file manipulation. These vulnerabilities include multiple
memory safety errors, buffer overflows, use-after-frees and other
implementation errors may lead to the execution of arbitrary code, the
bypass of security restrictions, path traversal attack or denial of
service.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/03/msg00021.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/binutils"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-gold");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-multiarch");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:binutils-source");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/30");
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
if (deb_check(release:"6.0", prefix:"binutils", reference:"2.20.1-16+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-dev", reference:"2.20.1-16+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-doc", reference:"2.20.1-16+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-gold", reference:"2.20.1-16+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-multiarch", reference:"2.20.1-16+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"binutils-source", reference:"2.20.1-16+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
