#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3238. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(83120);
  script_version("$Revision: 2.9 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2015-1235", "CVE-2015-1236", "CVE-2015-1237", "CVE-2015-1238", "CVE-2015-1240", "CVE-2015-1241", "CVE-2015-1242", "CVE-2015-1244", "CVE-2015-1245", "CVE-2015-1246", "CVE-2015-1247", "CVE-2015-1248", "CVE-2015-1249", "CVE-2015-3333", "CVE-2015-3334", "CVE-2015-3336");
  script_bugtraq_id(74165, 74167, 74221, 74225, 74227);
  script_osvdb_id(117805, 120749, 120750, 120751, 120752, 120753, 120754, 120755, 120757, 120758, 120759, 120760, 120805, 120806, 120827, 120829, 120831, 120832, 120852, 120853, 120854, 120864, 120866, 120867, 120868, 120869, 120882, 120883, 120884, 120909, 120910, 120911, 120913, 120914, 120917);
  script_xref(name:"DSA", value:"3238");

  script_name(english:"Debian DSA-3238-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the chromium web browser.

  - CVE-2015-1235
    A Same Origin Policy bypass issue was discovered in the
    HTML parser.

  - CVE-2015-1236
    Amitay Dobo discovered a Same Origin Policy bypass in
    the Web Audio API.

  - CVE-2015-1237
    Khalil Zhani discovered a use-after-free issue in IPC.

  - CVE-2015-1238
    'cloudfuzzer' discovered an out-of-bounds write in the
    skia library.

  - CVE-2015-1240
    'w3bd3vil' discovered an out-of-bounds read in the WebGL
    implementation.

  - CVE-2015-1241
    Phillip Moon and Matt Weston discovered a way to trigger
    local user interface actions remotely via a crafted
    website.

  - CVE-2015-1242
    A type confusion issue was discovered in the v8
    JavaScript library.

  - CVE-2015-1244
    Mike Ruddy discovered a way to bypass the HTTP Strict
    Transport Security policy.

  - CVE-2015-1245
    Khalil Zhani discovered a use-after-free issue in the
    pdfium library.

  - CVE-2015-1246
    Atte Kettunen discovered an out-of-bounds read issue in
    webkit/blink.

  - CVE-2015-1247
    Jann Horn discovered that 'file:' URLs in OpenSearch
    documents were not sanitized, which could allow local
    files to be read remotely when using the OpenSearch
    feature from a crafted website.

  - CVE-2015-1248
    Vittorio Gambaletta discovered a way to bypass the
    SafeBrowsing feature, which could allow the remote
    execution of a downloaded executable file.

  - CVE-2015-1249
    The chrome 41 development team found various issues from
    internal fuzzing, audits, and other studies.

  - CVE-2015-3333
    Multiple issues were discovered and fixed in v8
    4.2.7.14.

  - CVE-2015-3334
    It was discovered that remote websites could capture
    video data from attached web cameras without permission.

  - CVE-2015-3336
    It was discovered that remote websites could cause user
    interface disruptions like window fullscreening and
    mouse pointer locking."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1235"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1236"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1240"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1245"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1247"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1249"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3336"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3238"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 42.0.2311.90-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/29");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"42.0.2311.90-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"42.0.2311.90-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"42.0.2311.90-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"42.0.2311.90-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"42.0.2311.90-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
