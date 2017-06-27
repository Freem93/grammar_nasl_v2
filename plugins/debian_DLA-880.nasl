#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-880-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99107);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/31 13:26:14 $");

  script_cve_id("CVE-2015-8781", "CVE-2015-8782", "CVE-2015-8783", "CVE-2015-8784", "CVE-2016-9533", "CVE-2016-9534", "CVE-2016-9535");
  script_osvdb_id(118377, 133559, 133560, 133561, 133569, 145021, 145022, 147758);

  script_name(english:"Debian DLA-880-1 : tiff3 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"tiff3 is affected by multiple issues that can result at least in
denial of services of applications using libtiff4. Crafted TIFF files
can be provided to trigger: abort() calls via failing assertions,
buffer overruns (both in read and write mode).

CVE-2015-8781

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds write) via an invalid number of samples per pixel in a
LogL compressed TIFF image.

CVE-2015-8782

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds writes) via a crafted TIFF image.

CVE-2015-8783

tif_luv.c in libtiff allows attackers to cause a denial of service
(out-of-bounds reads) via a crafted TIFF image.

CVE-2015-8784

The NeXTDecode function in tif_next.c in LibTIFF allows remote
attackers to cause a denial of service (out-of-bounds write) via a
crafted TIFF image.

CVE-2016-9533

tif_pixarlog.c in libtiff 4.0.6 has out-of-bounds write
vulnerabilities in heap allocated buffers.

CVE-2016-9534

tif_write.c in libtiff 4.0.6 has an issue in the error code path of
TIFFFlushData1() that didn't reset the tif_rawcc and tif_rawcp
members. 

CVE-2016-9535

tif_predict.h and tif_predict.c in libtiff 4.0.6 have assertions that
can lead to assertion failures in debug mode, or buffer overflows in
release mode, when dealing with unusual tile size like YCbCr with
subsampling.

For Debian 7 'Wheezy', these problems have been fixed in version
3.9.6-11+deb7u4.

We recommend that you upgrade your tiff3 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/03/msg00039.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/tiff3"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiff4-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libtiffxx0c2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/31");
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
if (deb_check(release:"7.0", prefix:"libtiff4", reference:"3.9.6-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtiff4-dev", reference:"3.9.6-11+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libtiffxx0c2", reference:"3.9.6-11+deb7u4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
