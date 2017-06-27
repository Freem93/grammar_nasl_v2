#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-905-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(99544);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/04/21 13:44:39 $");

  script_cve_id("CVE-2016-10219", "CVE-2016-10220", "CVE-2017-5951");
  script_osvdb_id(154925, 154981, 154982);

  script_name(english:"Debian DLA-905-1 : ghostscript security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"ghostscript is vulnerable to multiple issues that can lead to denial
of service when processing untrusted content.

CVE-2016-10219

Application crash with division by 0 in scan conversion code triggered
through crafted content.

CVE-2016-10220

Application crash with a segfault in gx_device_finalize() triggered
through crafted content.

CVE-2017-5951

Application crash with a segfault in ref_stack_index() triggered
through crafted content.

For Debian 7 'Wheezy', these problems have been fixed in version
9.05~dfsg-6.3+deb7u5.

We recommend that you upgrade your ghostscript packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2017/04/msg00024.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/ghostscript"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-cups");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ghostscript-x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libgs9-common");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/21");
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
if (deb_check(release:"7.0", prefix:"ghostscript", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"ghostscript-cups", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"ghostscript-dbg", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"ghostscript-doc", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"ghostscript-x", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgs-dev", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgs9", reference:"9.05~dfsg-6.3+deb7u5")) flag++;
if (deb_check(release:"7.0", prefix:"libgs9-common", reference:"9.05~dfsg-6.3+deb7u5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
