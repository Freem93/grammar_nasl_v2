#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3549. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(90549);
  script_version("$Revision: 2.10 $");
  script_cvs_date("$Date: 2016/12/06 20:25:08 $");

  script_cve_id("CVE-2016-1651", "CVE-2016-1652", "CVE-2016-1653", "CVE-2016-1654", "CVE-2016-1655", "CVE-2016-1657", "CVE-2016-1658", "CVE-2016-1659");
  script_osvdb_id(120616, 130175, 131598, 135124, 137041, 137042, 137044, 137046, 137047, 137048, 137051, 137052, 137053, 137054, 137055, 137056, 137057, 137058, 137059, 137060, 137061);
  script_xref(name:"DSA", value:"3549");

  script_name(english:"Debian DSA-3549-1 : chromium-browser - security update");
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

  - CVE-2016-1651
    An out-of-bounds read issue was discovered in the pdfium
    library.

  - CVE-2016-1652
    A cross-site scripting issue was discovered in extension
    bindings.

  - CVE-2016-1653
    Choongwoo Han discovered an out-of-bounds write issue in
    the v8 JavaScript library.

  - CVE-2016-1654
    Atte Kettunen discovered an uninitialized memory read
    condition.

  - CVE-2016-1655
    Rob Wu discovered a use-after-free issue related to
    extensions.

  - CVE-2016-1657
    Luan Herrera discovered a way to spoof URLs.

  - CVE-2016-1658
    Antonio Sanso discovered an information leak related to
    extensions.

  - CVE-2016-1659
    The chrome development team found and fixed various
    issues during internal auditing."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1651"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1652"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1653"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1655"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1657"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1658"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2016-1659"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2016/dsa-3549"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (jessie), these problems have been fixed
in version 50.0.2661.75-1~deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/04/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/04/18");
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
if (deb_check(release:"8.0", prefix:"chromedriver", reference:"50.0.2661.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium", reference:"50.0.2661.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-dbg", reference:"50.0.2661.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-inspector", reference:"50.0.2661.75-1~deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"chromium-l10n", reference:"50.0.2661.75-1~deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
