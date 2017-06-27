#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-547-2. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(92665);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2017/03/30 13:31:42 $");

  script_cve_id("CVE-2016-5240");
  script_osvdb_id(137975, 147270);

  script_name(english:"Debian DLA-547-2 : graphicsmagick regression update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The fix for CVE-2016-5240 was improperly applied which resulted in
GraphicsMagick crashing instead of entering an infinite loop with the
given proof of concept.

Furthermore, the original announcement mistakently used the identifier
'DLA 574-1' instead of the correct one, 'DLA 547-1'.

For Debian 7 'Wheezy', these problems have been fixed in version
1.3.16-1.1+deb7u6.

We recommend that you upgrade your graphicsmagick packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00037.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/graphicsmagick"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

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

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/08/02");
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
if (deb_check(release:"7.0", prefix:"graphicsmagick", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-dbg", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-imagemagick-compat", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"graphicsmagick-libmagick-dev-compat", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphics-magick-perl", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick++1-dev", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick++3", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick1-dev", reference:"1.3.16-1.1+deb7u6")) flag++;
if (deb_check(release:"7.0", prefix:"libgraphicsmagick3", reference:"1.3.16-1.1+deb7u6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
