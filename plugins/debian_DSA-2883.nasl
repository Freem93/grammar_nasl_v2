#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2883. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(73164);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:43:11 $");

  script_cve_id("CVE-2013-6653", "CVE-2013-6654", "CVE-2013-6655", "CVE-2013-6656", "CVE-2013-6657", "CVE-2013-6658", "CVE-2013-6659", "CVE-2013-6660", "CVE-2013-6661", "CVE-2013-6663", "CVE-2013-6664", "CVE-2013-6665", "CVE-2013-6666", "CVE-2013-6667", "CVE-2013-6668", "CVE-2014-1700", "CVE-2014-1701", "CVE-2014-1702", "CVE-2014-1703", "CVE-2014-1704", "CVE-2014-1705", "CVE-2014-1713", "CVE-2014-1715");
  script_bugtraq_id(65699, 65930, 66120, 66239, 66243, 66249);
  script_xref(name:"DSA", value:"2883");

  script_name(english:"Debian DSA-2883-1 : chromium-browser - security update");
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

  - CVE-2013-6653
    Khalil Zhani discovered a use-after-free issue in
    chromium's web contents color chooser.

  - CVE-2013-6654
    TheShow3511 discovered an issue in SVG handling.

  - CVE-2013-6655
    cloudfuzzer discovered a use-after-free issue in dom
    event handling.

  - CVE-2013-6656
    NeexEmil discovered an information leak in the XSS
    auditor.

  - CVE-2013-6657
    NeexEmil discovered a way to bypass the Same Origin
    policy in the XSS auditor.

  - CVE-2013-6658
    cloudfuzzer discovered multiple use-after-free issues
    surrounding the updateWidgetPositions function.

  - CVE-2013-6659
    Antoine Delignat-Lavaud and Karthikeyan Bhargavan
    discovered that it was possible to trigger an unexpected
    certificate chain during TLS renegotiation.

  - CVE-2013-6660
    bishopjeffreys discovered an information leak in the
    drag and drop implementation.

  - CVE-2013-6661
    The Google Chrome team discovered and fixed multiple
    issues in version 33.0.1750.117.

  - CVE-2013-6663
    Atte Kettunen discovered a use-after-free issue in SVG
    handling.

  - CVE-2013-6664
    Khalil Zhani discovered a use-after-free issue in the
    speech recognition feature.

  - CVE-2013-6665
    cloudfuzzer discovered a buffer overflow issue in the
    software renderer.

  - CVE-2013-6666
    netfuzzer discovered a restriction bypass in the Pepper
    Flash plugin.

  - CVE-2013-6667
    The Google Chrome team discovered and fixed multiple
    issues in version 33.0.1750.146.

  - CVE-2013-6668
    Multiple vulnerabilities were fixed in version
    3.24.35.10 of the V8 JavaScript library.

  - CVE-2014-1700
    Chamal de Silva discovered a use-after-free issue in
    speech synthesis.

  - CVE-2014-1701
    aidanhs discovered a cross-site scripting issue in event
    handling.

  - CVE-2014-1702
    Colin Payne discovered a use-after-free issue in the web
    database implementation.

  - CVE-2014-1703
    VUPEN discovered a use-after-free issue in web sockets
    that could lead to a sandbox escape.

  - CVE-2014-1704
    Multiple vulnerabilities were fixed in version
    3.23.17.18 of the V8 JavaScript library.

  - CVE-2014-1705
    A memory corruption issue was discovered in the V8
    JavaScript library.

  - CVE-2014-1713
    A use-after-free issue was discovered in the
    AttributeSetter function.

  - CVE-2014-1715
    A directory traversal issue was found and fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6656"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6660"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6661"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6663"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6664"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6665"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6666"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6667"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-6668"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1700"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1702"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1705"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1715"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2883"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 33.0.1750.152-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/03/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/03/25");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"33.0.1750.152-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"33.0.1750.152-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
