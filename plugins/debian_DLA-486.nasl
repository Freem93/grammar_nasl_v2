#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-486-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91287);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_osvdb_id(137951, 137952, 137953, 137954, 137955);

  script_name(english:"Debian DLA-486-1 : imagemagick security update (ImageTragick)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nikolay Ermishkin from the Mail.Ru Security Team and Stewie discovered
several vulnerabilities in ImageMagick, a program suite for image
manipulation. These vulnerabilities, collectively known as
ImageTragick, are the consequence of lack of sanitization of untrusted
input. An attacker with control on the image input could, with the
privileges of the user running the application, execute code
(CVE-2016-3714), make HTTP GET or FTP requests (CVE-2016-3718), or
delete (CVE-2016-3715), move (CVE-2016-3716), or read (CVE-2016-3717)
local files.

These vulnerabilities are particularly critical if Imagemagick
processes images coming from remote parties, such as part of a web
service.

The update disables the vulnerable coders (EPHEMERAL, URL, MVG, MSL,
and PLT) and indirect reads via /etc/ImageMagick/policy.xml file. In
addition, we introduce extra preventions, including some sanitization
for input filenames in http/https delegates, the full remotion of
PLT/Gnuplot decoder, and the need of explicit reference in the
filename for the insecure coders.

For the wheezy, these problems have been fixed in version
8:6.7.7.10-5+deb7u5.

We recommend that you upgrade your imagemagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/imagemagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:imagemagick-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagick++5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickcore5-extra");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmagickwand5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:perlmagick");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/22");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/23");
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
if (deb_check(release:"7.0", prefix:"imagemagick", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-common", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-dbg", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"imagemagick-doc", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++-dev", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagick++5", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore-dev", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickcore5-extra", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand-dev", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libmagickwand5", reference:"8:6.7.7.10-5+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"perlmagick", reference:"8:6.7.7.10-5+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
