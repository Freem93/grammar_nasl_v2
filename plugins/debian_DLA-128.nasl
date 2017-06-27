#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-128-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82111);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_cve_id("CVE-2014-8145");
  script_bugtraq_id(71774);

  script_name(english:"Debian DLA-128-1 : sox security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Michele Spagnuolo of the Google Security Team discovered two heap-based
buffer overflows in SoX, the Swiss Army knife of sound processing
programs. A specially crafted wav file could cause an application
using SoX to crash or, possibly, execute arbitrary code.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/01/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/sox"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-all");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-alsa");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-ao");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-base");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-ffmpeg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-mp3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-oss");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox-fmt-pulse");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsox1b");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sox");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/01/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"libsox-dev", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-all", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-alsa", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-ao", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-base", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-ffmpeg", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-mp3", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-oss", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox-fmt-pulse", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libsox1b", reference:"14.3.1-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"sox", reference:"14.3.1-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
