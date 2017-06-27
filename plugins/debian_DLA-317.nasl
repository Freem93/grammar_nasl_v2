#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-317-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86196);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2014-9638", "CVE-2014-9639", "CVE-2014-9640", "CVE-2015-6749");
  script_bugtraq_id(72290, 72292, 72295);
  script_osvdb_id(126296);

  script_name(english:"Debian DLA-317-1 : vorbis-tools security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various issues have been fixed in Debian LTS (squeeze) for package
vorbis-tools.

CVE-2014-9638

A crafted WAV file with number of channels set to 0 will cause oggenc
to crash due to a division by zero issue. This issue has been fixed
upstream by providing a fix for CVE-2014-9639. Reported upstream by
'zuBux'.

CVE-2014-9639

An integer overflow issue was discovered in oggenc, related to the
number of channels in the input WAV file. The issue triggers an
out-of-bounds memory access which causes oggenc to crash here
(audio.c). Reported upstream by 'zuBux'.

The upstream fix for this has been backported to
vorbis-tools in Debian LTS (squeeze).

CVE-2014-9640

Fix for a crash on closing raw input (dd if=/dev/zero bs=1 count=1 |
oggenc -r - -o out.ogg). Reported upstream by 'hanno'.

The upstream fix for this has been backported to
vorbis-tools in Debian LTS (squeeze).

CVE-2015-6749

Buffer overflow in the aiff_open function in oggenc/audio.c in
vorbis-tools 1.4.0 and earlier allowed remote attackers to cause a
denial of service (crash) via a crafted AIFF file. Reported upstream
by 'pengsu'.

The upstream fix for this has been backported to
vorbis-tools in Debian LTS (squeeze).

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/vorbis-tools"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected vorbis-tools, and vorbis-tools-dbg packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vorbis-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:vorbis-tools-dbg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/30");
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
if (deb_check(release:"6.0", prefix:"vorbis-tools", reference:"1.4.0-1+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"vorbis-tools-dbg", reference:"1.4.0-1+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
