#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3039. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(77973);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/09/06 13:33:34 $");

  script_cve_id("CVE-2014-3160", "CVE-2014-3162", "CVE-2014-3165", "CVE-2014-3166", "CVE-2014-3167", "CVE-2014-3168", "CVE-2014-3169", "CVE-2014-3170", "CVE-2014-3171", "CVE-2014-3172", "CVE-2014-3173", "CVE-2014-3174", "CVE-2014-3175", "CVE-2014-3176", "CVE-2014-3177", "CVE-2014-3178", "CVE-2014-3179");
  script_bugtraq_id(68677, 69201, 69202, 69203, 69398, 69400, 69401, 69402, 69403, 69404, 69405, 69406, 69407, 69709, 69710);
  script_osvdb_id(110508, 110540, 115894, 115895, 115896, 115897, 115898, 115899, 115900, 115901, 115902, 115903, 115904, 115905, 115906, 115907, 115908, 115909);
  script_xref(name:"DSA", value:"3039");

  script_name(english:"Debian DSA-3039-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the chromium web browser.

  - CVE-2014-3160
    Christian Schneider discovered a same origin bypass
    issue in SVG file resource fetching.

  - CVE-2014-3162
    The Google Chrome development team addressed multiple
    issues with potential security impact for chromium
    36.0.1985.125.

  - CVE-2014-3165
    Colin Payne discovered a use-after-free issue in the Web
    Sockets implementation.

  - CVE-2014-3166
    Antoine Delignat-Lavaud discovered an information leak
    in the SPDY protocol implementation.

  - CVE-2014-3167
    The Google Chrome development team addressed multiple
    issues with potential security impact for chromium
    36.0.1985.143.

  - CVE-2014-3168
    cloudfuzzer discovered a use-after-free issue in SVG
    image file handling.

  - CVE-2014-3169
    Andrzej Dyjak discovered a use-after-free issue in the
    Webkit/Blink Document Object Model implementation.

  - CVE-2014-3170
    Rob Wu discovered a way to spoof the url of chromium
    extensions.

  - CVE-2014-3171
    cloudfuzzer discovered a use-after-free issue in
    chromium's v8 bindings.

  - CVE-2014-3172
    Eli Grey discovered a way to bypass access restrictions
    using chromium's Debugger extension API.

  - CVE-2014-3173
    jmuizelaar discovered an uninitialized read issue in
    WebGL.

  - CVE-2014-3174
    Atte Kettunen discovered an uninitialized read issue in
    Web Audio.

  - CVE-2014-3175
    The Google Chrome development team addressed multiple
    issues with potential security impact for chromium
    37.0.2062.94.

  - CVE-2014-3176
    lokihardt@asrt discovered a combination of flaws that
    can lead to remote code execution outside of chromium's
    sandbox.

  - CVE-2014-3177
    lokihardt@asrt discovered a combination of flaws that
    can lead to remote code execution outside of chromium's
    sandbox.

  - CVE-2014-3178
    miaubiz discovered a use-after-free issue in the
    Document Object Model implementation in Blink/Webkit.

  - CVE-2014-3179
    The Google Chrome development team addressed multiple
    issues with potential security impact for chromium
    37.0.2062.120."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3162"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3165"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3167"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3168"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3172"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3175"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3039"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 37.0.2062.120-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"37.0.2062.120-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"37.0.2062.120-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
