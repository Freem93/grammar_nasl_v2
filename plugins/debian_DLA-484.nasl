#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-484-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(91299);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-8808", "CVE-2016-2317", "CVE-2016-2318", "CVE-2016-3714", "CVE-2016-3715", "CVE-2016-3716", "CVE-2016-3717", "CVE-2016-3718");
  script_osvdb_id(134375, 134437, 134439, 134440, 134441, 134442, 134443, 137951, 137952, 137953, 137954, 137955);

  script_name(english:"Debian DLA-484-1 : graphicsmagick security update (ImageTragick)");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security vulnerabilities were discovered in graphicsmagick a
tool to manipulate image files.

GraphicsMagick is a fork of ImageMagick and also affected by
vulnerabilities collectively known as ImageTragick, that are the
consequence of lack of sanitization of untrusted input. An attacker
with control on the image input could, with the privileges of the user
running the application, execute code (CVE-2016-3714), make HTTP GET
or FTP requests (CVE-2016-3718), or delete (CVE-2016-3715), move
(CVE-2016-3716), or read (CVE-2016-3717) local files.

To address these concerns the following changes have been made :

1. Remove automatic detection/execution of MVG based on file header or
file extension.

2. Remove the ability to cause an input file to be deleted based on a
filename specification.

3. Improve the safety of delegates.mgk by removing gnuplot support,
removing manual page support, and by adding -dSAFER to all ghostscript
invocations.

4. Sanity check the MVG image primitive filename argument to assure
that 'magick:' prefix strings will not be interpreted. Please note
that this patch will break intentional uses of magick prefix strings
in MVG and so some MVG scripts may fail. We will search for a more
flexible solution.

In addition the following issues have been fixed :

CVE-2015-8808 Assure that GIF decoder does not use unitialized data
and cause an out-of-bound read.

CVE-2016-2317 and CVE-2016-2318 Vulnerabilities that allow to read or
write outside memory bounds (heap, stack) as well as some NULL pointer
derreferences to cause a denial of service when parsing SVG files.

For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u1.

We recommend that you upgrade your graphicsmagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/05/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/graphicsmagick"
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-imagemagick-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:graphicsmagick-libmagick-dev-compat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphics-magick-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick++3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgraphicsmagick3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/21");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/24");
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
if (deb_check(release:"7.0", prefix:"graphicsmagick", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-dbg", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphics-magick-perl", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick++3", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.16-1.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick3", reference:"1.3.16-1.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
