#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-405-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(88491);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2016/12/06 20:03:51 $");

  script_cve_id("CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784");
  script_osvdb_id(118377, 133559, 133560, 133561, 133569);

  script_name(english:"Debian DLA-405-1 : tiff security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security flaws have been found and solved in libtiff, a
library that provides support for handling Tag Image File Format
(TIFF). These flaws concern out of bounds reads and writes in the
LogL16Decode, LogLuvDecode24, LogLuvDecode32, LogLuvDecodeTile,
LogL16Encode, LogLuvEncode24, LogLuvEncode32 and NeXTDecode functions.

These IDs were assigned for the problems: CVE-2015-8781,
CVE-2015-8782, CVE-2015-8783 and CVE-2015-8784.

For Debian 6 'Squeeze', these issues have been fixed in tiff version
3.9.4-5+squeeze14. We recommend you to upgrade your tiff packages.

Learn more about the Debian Long Term Support (LTS) Project and how to
apply these updates at: https://wiki.debian.org/LTS/

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2016/01/msg00030.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/tiff"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://wiki.debian.org/LTS/"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-opengl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx0c2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/02/01");
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
if (deb_check(release:"6.0", prefix:"libtiff-doc", reference:"3.9.4-5+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-opengl", reference:"3.9.4-5+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff-tools", reference:"3.9.4-5+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4", reference:"3.9.4-5+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libtiff4-dev", reference:"3.9.4-5+squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libtiffxx0c2", reference:"3.9.4-5+squeeze14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
