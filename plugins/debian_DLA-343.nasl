#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-343-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86907);
  script_version("$Revision: 2.6 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2012-3425", "CVE-2015-7981", "CVE-2015-8126");
  script_bugtraq_id(54652);
  script_osvdb_id(84389, 129444, 130175);

  script_name(english:"Debian DLA-343-1 : libpng security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"  - CVE-2015-7981 Added a safety check in png_set_tIME()
    (Bug report from Qixue Xiao).

  - CVE-2015-8126 Multiple buffer overflows in the (1)
    png_set_PLTE and (2) png_get_PLTE functions in libpng
    before 1.0.64, 1.1.x and 1.2.x before 1.2.54, 1.3.x and
    1.4.x before 1.4.17, 1.5.x before 1.5.24, and 1.6.x
    before 1.6.19 allow remote attackers to cause a denial
    of service (application crash) or possibly have
    unspecified other impact via a small bit-depth value in
    an IHDR (aka image header) chunk in a PNG image.

  - CVE-2012-3425 vulnerable code is not present here

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00003.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/libpng"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng12-0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng12-0-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng12-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libpng3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/18");
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
if (deb_check(release:"6.0", prefix:"libpng12-0", reference:"1.2.44-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-0-udeb", reference:"1.2.44-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libpng12-dev", reference:"1.2.44-1+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"libpng3", reference:"1.2.44-1+squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
