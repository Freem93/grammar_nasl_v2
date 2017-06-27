#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3776. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(96885);
  script_version("$Revision: 3.8 $");
  script_cvs_date("$Date: 2017/03/20 15:44:32 $");

  script_cve_id("CVE-2017-5006", "CVE-2017-5007", "CVE-2017-5008", "CVE-2017-5009", "CVE-2017-5010", "CVE-2017-5011", "CVE-2017-5012", "CVE-2017-5013", "CVE-2017-5014", "CVE-2017-5015", "CVE-2017-5016", "CVE-2017-5017", "CVE-2017-5018", "CVE-2017-5019", "CVE-2017-5020", "CVE-2017-5021", "CVE-2017-5022", "CVE-2017-5023", "CVE-2017-5024", "CVE-2017-5025", "CVE-2017-5026");
  script_osvdb_id(150936, 150937, 150938, 150939, 150940, 150941, 150942, 150943, 150944, 150945, 150946, 150947, 150948, 150949, 150950, 150951, 150952, 150953, 150954, 150966, 150967);
  script_xref(name:"DSA", value:"3776");

  script_name(english:"Debian DSA-3776-1 : chromium-browser - security update");
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

  - CVE-2017-5006
    Mariusz Mlynski discovered a cross-site scripting issue.

  - CVE-2017-5007
    Mariusz Mlynski discovered another cross-site scripting
    issue.

  - CVE-2017-5008
    Mariusz Mlynski discovered a third cross-site scripting
    issue.

  - CVE-2017-5009
    Sean Stanek and Chip Bradford discovered an
    out-of-bounds memory issue in the webrtc library.

  - CVE-2017-5010
    Mariusz Mlynski discovered a fourth cross-site scripting
    issue.

  - CVE-2017-5011
    Khalil Zhani discovered a way to access unauthorized
    files in the developer tools.

  - CVE-2017-5012
    Gergely Nagy discovered a heap overflow issue in the v8
    JavaScript library.

  - CVE-2017-5013
    Haosheng Wang discovered a URL spoofing issue.

  - CVE-2017-5014
    sweetchip discovered a heap overflow issue in the skia
    library.

  - CVE-2017-5015
    Armin Razmdjou discovered a URL spoofing issue.

  - CVE-2017-5016
    Haosheng Wang discovered another URL spoofing issue.

  - CVE-2017-5017
    danberm discovered an uninitialized memory issue in
    support for webm video files.

  - CVE-2017-5018
    Rob Wu discovered a cross-site scripting issue.

  - CVE-2017-5019
    Wadih Matar discovered a use-after-free issue.

  - CVE-2017-5020
    Rob Wu discovered another cross-site scripting issue.

  - CVE-2017-5021
    Rob Wu discovered a use-after-free issue in extensions.

  - CVE-2017-5022
    PKAV Team discovered a way to bypass the Content
    Security Policy.

  - CVE-2017-5023
    UK's National Cyber Security Centre (NCSC) discovered a
    type confusion issue.

  - CVE-2017-5024
    Paul Mehta discovered a heap overflow issue in the
    ffmpeg library.

  - CVE-2017-5025
    Paul Mehta discovered another heap overflow issue in the
    ffmpeg library.

  - CVE-2017-5026
    Ronni Skansing discovered a user interface spoofing
    issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5006"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5007"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5008"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5009"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5010"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5011"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5012"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5013"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5016"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5017"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5018"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5019"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5020"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5021"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5022"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5023"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5024"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5025"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2017-5026"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2017/dsa-3776"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 56.0.2924.76-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/01/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/01/31");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"56.0.2924.76-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"56.0.2924.76-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"56.0.2924.76-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"56.0.2924.76-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"56.0.2924.76-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
