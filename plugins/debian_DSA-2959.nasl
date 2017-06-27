#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2959. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(76057);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:48:47 $");

  script_cve_id("CVE-2014-3154", "CVE-2014-3155", "CVE-2014-3156", "CVE-2014-3157");
  script_bugtraq_id(67972, 67977, 67980, 67981);
  script_xref(name:"DSA", value:"2959");

  script_name(english:"Debian DSA-2959-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the chromium web
browser.

  - CVE-2014-3154
    Collin Payne discovered a use-after-free issue in the
    filesystem API.

  - CVE-2014-3155
    James March, Daniel Sommermann, and Alan Frindell
    discovered several out-of-bounds read issues in the SPDY
    protocol implementation.

  - CVE-2014-3156
    Atte Kettunen discovered a buffer overflow issue in
    bitmap handling in the clipboard implementation.

  - CVE-2014-3157
    A heap-based buffer overflow issue was discovered in
    chromium's ffmpeg media filter.

In addition, this version corrects a regression in the previous
update. Support for older i386 processors had been dropped. This
functionality is now restored."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3155"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3156"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3157"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2959"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 35.0.1916.153-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/16");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"35.0.1916.153-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"35.0.1916.153-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
