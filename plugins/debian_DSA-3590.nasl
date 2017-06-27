#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3590. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(91429);
  script_version("$Revision: 2.11 $");
  script_cvs_date("$Date: 2017/03/13 15:28:55 $");

  script_cve_id("CVE-2016-1667", "CVE-2016-1668", "CVE-2016-1669", "CVE-2016-1670", "CVE-2016-1672", "CVE-2016-1673", "CVE-2016-1674", "CVE-2016-1675", "CVE-2016-1676", "CVE-2016-1677", "CVE-2016-1678", "CVE-2016-1679", "CVE-2016-1680", "CVE-2016-1681", "CVE-2016-1682", "CVE-2016-1683", "CVE-2016-1684", "CVE-2016-1685", "CVE-2016-1686", "CVE-2016-1687", "CVE-2016-1688", "CVE-2016-1689", "CVE-2016-1690", "CVE-2016-1691", "CVE-2016-1692", "CVE-2016-1693", "CVE-2016-1694", "CVE-2016-1695");
  script_osvdb_id(120600, 121175, 129696, 130292, 130435, 130535, 130536, 130538, 130539, 130543, 130641, 130642, 130651, 135603, 137043, 137788, 138417, 138418, 138419, 138796, 139022, 139023, 139024, 139025, 139026, 139027, 139028, 139029, 139030, 139031, 139032, 139033, 139034, 139035, 139036, 139037, 139038, 139039, 139040, 139041, 139042, 139043, 139087, 139088, 139091, 139096, 139099, 139100, 139101, 139106, 139107, 139108, 139109, 139110, 139114, 139186, 139187, 139190, 139191, 139192, 140427);
  script_xref(name:"DSA", value:"3590");

  script_name(english:"Debian DSA-3590-1 : chromium-browser - security update");
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

  - CVE-2016-1667
    Mariusz Mylinski discovered a cross-origin bypass.

  - CVE-2016-1668
    Mariusz Mylinski discovered a cross-origin bypass in
    bindings to v8.

  - CVE-2016-1669
    Choongwoo Han discovered a buffer overflow in the v8
    JavaScript library.

  - CVE-2016-1670
    A race condition was found that could cause the renderer
    process to reuse ids that should have been unique.

  - CVE-2016-1672
    Mariusz Mylinski discovered a cross-origin bypass in
    extension bindings.

  - CVE-2016-1673
    Mariusz Mylinski discovered a cross-origin bypass in
    Blink/Webkit.

  - CVE-2016-1674
    Mariusz Mylinski discovered another cross-origin bypass
    in extension bindings.

  - CVE-2016-1675
    Mariusz Mylinski discovered another cross-origin bypass
    in Blink/Webkit.

  - CVE-2016-1676
    Rob Wu discovered a cross-origin bypass in extension
    bindings.

  - CVE-2016-1677
    Guang Gong discovered a type confusion issue in the v8
    JavaScript library.

  - CVE-2016-1678
    Christian Holler discovered an overflow issue in the v8
    JavaScript library.

  - CVE-2016-1679
    Rob Wu discovered a use-after-free issue in the bindings
    to v8.

  - CVE-2016-1680
    Atte Kettunen discovered a use-after-free issue in the
    skia library.

  - CVE-2016-1681
    Aleksandar Nikolic discovered an overflow issue in the
    pdfium library.

  - CVE-2016-1682
    KingstonTime discovered a way to bypass the Content
    Security Policy.

  - CVE-2016-1683
    Nicolas Gregoire discovered an out-of-bounds write issue
    in the libxslt library.

  - CVE-2016-1684
    Nicolas Gregoire discovered an integer overflow issue in
    the libxslt library.

  - CVE-2016-1685
    Ke Liu discovered an out-of-bounds read issue in the
    pdfium library.

  - CVE-2016-1686
    Ke Liu discovered another out-of-bounds read issue in
    the pdfium library.

  - CVE-2016-1687
    Rob Wu discovered an information leak in the handling of
    extensions.

  - CVE-2016-1688
    Max Korenko discovered an out-of-bounds read issue in
    the v8 JavaScript library.

  - CVE-2016-1689
    Rob Wu discovered a buffer overflow issue.

  - CVE-2016-1690
    Rob Wu discovered a use-after-free issue.

  - CVE-2016-1691
    Atte Kettunen discovered a buffer overflow issue in the
    skia library.

  - CVE-2016-1692
    Til Jasper Ullrich discovered a cross-origin bypass
    issue.

  - CVE-2016-1693
    Khalil Zhani discovered that the Software Removal Tool
    download was done over an HTTP connection.

  - CVE-2016-1694
    Ryan Lester and Bryant Zadegan discovered that pinned
    public keys would be removed when clearing the browser
    cache.

  - CVE-2016-1695
    The chrome development team found and fixed various
    issues during internal auditing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1670"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1672"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1673"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1674"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1675"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1676"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1677"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1678"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1679"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1680"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1681"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1682"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1683"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1684"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1685"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1686"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1687"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1688"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1691"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3590"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 51.0.2704.63-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:ND/RC:UR");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:X/RC:R");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/02");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"51.0.2704.63-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"51.0.2704.63-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
