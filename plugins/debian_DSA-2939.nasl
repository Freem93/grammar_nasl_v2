#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2939. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74256);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2014-1743", "CVE-2014-1744", "CVE-2014-1745", "CVE-2014-1746", "CVE-2014-1747", "CVE-2014-1748", "CVE-2014-1749", "CVE-2014-3152");
  script_bugtraq_id(67517);
  script_osvdb_id(107144);
  script_xref(name:"DSA", value:"2939");

  script_name(english:"Debian DSA-2939-1 : chromium-browser - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the chromium web browser.

  - CVE-2014-1743
    cloudfuzzer discovered a use-after-free issue in the
    Blink/Webkit document object model implementation.

  - CVE-2014-1744
    Aaron Staple discovered an integer overflow issue in
    audio input handling.

  - CVE-2014-1745
    Atte Kettunen discovered a use-after-free issue in the
    Blink/Webkit scalable vector graphics implementation. 

  - CVE-2014-1746
    Holger Fuhrmannek discovered an out-of-bounds read issue
    in the URL protocol implementation for handling media.

  - CVE-2014-1747
    packagesu discovered a cross-site scripting issue
    involving malformed MHTML files.

  - CVE-2014-1748
    Jordan Milne discovered a user interface spoofing issue.

  - CVE-2014-1749
    The Google Chrome development team discovered and fixed
    multiple issues with potential security impact.

  - CVE-2014-3152
    An integer underflow issue was discovered in the v8
    JavaScript library."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1744"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1745"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1746"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1747"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1748"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3152"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2939"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (wheezy), these problems have been fixed
in version 35.0.1916.114-1~deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/02");
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
if (deb_check(release:"7.0", prefix:"chromium", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-dbg", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-inspector", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-browser-l10n", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-dbg", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-inspector", reference:"35.0.1916.114-1~deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"chromium-l10n", reference:"35.0.1916.114-1~deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
