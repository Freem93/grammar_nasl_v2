#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-928-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99739);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/01 13:40:22 $");

  script_cve_id("CVE-2015-7805", "CVE-2017-7585", "CVE-2017-7586", "CVE-2017-7741", "CVE-2017-7742");
  script_osvdb_id(128868, 155162, 155163, 155443, 155444);

  script_name(english:"Debian DLA-928-1 : libsndfile security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in libsndfile, a popular library
for reading/writing audio files.

CVE-2017-7585

In libsndfile before 1.0.28, an error in the 'flac_buffer_copy()'
function (flac.c) can be exploited to cause a stack-based buffer
overflow via a specially crafted FLAC file.

CVE-2017-7586

In libsndfile before 1.0.28, an error in the 'header_read()' function
(common.c) when handling ID3 tags can be exploited to cause a
stack-based buffer overflow via a specially crafted FLAC file.
CVE-2017-7741

In libsndfile before 1.0.28, an error in the
'flac_buffer_copy()' function (flac.c) can be exploited to
cause a segmentation violation (with write memory access)
via a specially crafted FLAC file during a resample attempt,
a similar issue to CVE-2017-7585. CVE-2017-7742

In libsndfile before 1.0.28, an error in the
'flac_buffer_copy()' function (flac.c) can be exploited to
cause a segmentation violation (with read memory access) via
a specially crafted FLAC file during a resample attempt, a
similar issue to CVE-2017-7585. CVE-2014-9496

The sd2_parse_rsrc_fork function in sd2.c in libsndfile
allows attackers to have unspecified impact via vectors
related to a (1) map offset or (2) rsrc marker, which
triggers an out-of-bounds read.

CVE-2014-9756

The psf_fwrite function in file_io.c in libsndfile allows attackers to
cause a denial of service (divide-by-zero error and application crash)
via unspecified vectors related to the headindex variable.
CVE-2015-7805

Heap-based buffer overflow in libsndfile 1.0.25 allows
remote attackers to have unspecified impact via the
headindex value in the header in an AIFF file.

For Debian 7 'Wheezy', these problems have been fixed in version
1.0.25-9.1+deb7u1.

We recommend that you upgrade your libsndfile packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00047.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libsndfile"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsndfile1");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libsndfile1-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sndfile-programs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libsndfile1", reference:"1.0.25-9.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libsndfile1-dev", reference:"1.0.25-9.1+deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"sndfile-programs", reference:"1.0.25-9.1+deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
