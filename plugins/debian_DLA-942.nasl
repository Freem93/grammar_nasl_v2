#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-942-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(100177);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/05/16 13:59:27 $");

  script_cve_id("CVE-2017-7885", "CVE-2017-7975", "CVE-2017-7976");
  script_osvdb_id(155690, 156072, 156073);

  script_name(english:"Debian DLA-942-1 : jbig2dec security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2017-7885 Artifex jbig2dec 0.13 has a heap-based buffer over-read
leading to denial of service (application crash) or disclosure of
sensitive information from process memory, because of an integer
overflow in the jbig2_decode_symbol_dict function in
jbig2_symbol_dict.c in libjbig2dec.a during operation on a crafted
.jb2 file.

CVE-2017-7975 Artifex jbig2dec 0.13, as used in Ghostscript, allows
out-of-bounds writes because of an integer overflow in the
jbig2_build_huffman_table function in jbig2_huffman.c during
operations on a crafted JBIG2 file, leading to a denial of service
(application crash) or possibly execution of arbitrary code.

CVE-2017-7976 Artifex jbig2dec 0.13 allows out-of-bounds writes and
reads because of an integer overflow in the jbig2_image_compose
function in jbig2_image.c during operations on a crafted .jb2 file,
leading to a denial of service (application crash) or disclosure of
sensitive information from process memory.

For Debian 7 'Wheezy', these problems have been fixed in version
0.13-4~deb7u2.

We recommend that you upgrade your jbig2dec packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/05/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/jbig2dec"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:jbig2dec");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjbig2dec0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libjbig2dec0-dev");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/05/16");
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
if (deb_check(release:"7.0", prefix:"jbig2dec", reference:"0.13-4~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libjbig2dec0", reference:"0.13-4~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libjbig2dec0-dev", reference:"0.13-4~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
