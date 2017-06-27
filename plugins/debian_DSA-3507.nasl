#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3507. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(89697);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/10/10 14:14:52 $");

  script_cve_id("CVE-2015-8126", "CVE-2016-1630", "CVE-2016-1631", "CVE-2016-1632", "CVE-2016-1633", "CVE-2016-1634", "CVE-2016-1635", "CVE-2016-1636", "CVE-2016-1637", "CVE-2016-1638", "CVE-2016-1639", "CVE-2016-1640", "CVE-2016-1641", "CVE-2016-1642");
  script_xref(name:"DSA", value:"3507");

  script_name(english:"Debian DSA-3507-1 : chromium-browser - security update");
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

  - CVE-2015-8126
    Joerg Bornemann discovered multiple buffer overflow
    issues in the libpng library.

  - CVE-2016-1630
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy in Blink/Webkit.

  - CVE-2016-1631
    Mariusz Mlynski discovered a way to bypass the Same
    Origin Policy in the Pepper Plugin API.

  - CVE-2016-1632
    A bad cast was discovered.

  - CVE-2016-1633
    cloudfuzzer discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2016-1634
    cloudfuzzer discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2016-1635
    Rob Wu discovered a use-after-free issue in
    Blink/Webkit.

  - CVE-2016-1636
    A way to bypass SubResource Integrity validation was
    discovered.

  - CVE-2016-1637
    Keve Nagy discovered an information leak in the skia
    library.

  - CVE-2016-1638
    Rob Wu discovered a WebAPI bypass issue.

  - CVE-2016-1639
    Khalil Zhani discovered a use-after-free issue in the
    WebRTC implementation.

  - CVE-2016-1640
    Luan Herrera discovered an issue with the Extensions
    user interface.

  - CVE-2016-1641
    Atte Kettunen discovered a use-after-free issue in the
    handling of favorite icons.

  - CVE-2016-1642
    The chrome 49 development team found and fixed various
    issues during internal auditing. Also multiple issues
    were fixed in the v8 JavaScript library, version
    4.9.385.26."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-8126"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1633"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1634"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1635"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1636"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1637"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3507"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 49.0.2623.75-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/07");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"49.0.2623.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"49.0.2623.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"49.0.2623.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"49.0.2623.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"49.0.2623.75-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
