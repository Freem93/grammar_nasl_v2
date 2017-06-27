#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2245. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55033);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-1292", "CVE-2011-1293", "CVE-2011-1440", "CVE-2011-1444", "CVE-2011-1797", "CVE-2011-1799");
  script_bugtraq_id(47029, 47604, 47830);
  script_osvdb_id(72205, 72209, 72265, 72266, 72369, 74016);
  script_xref(name:"DSA", value:"2245");

  script_name(english:"Debian DSA-2245-1 : chromium-browser - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in the Chromium browser. The
Common Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2011-1292
    Use-after-free vulnerability in the frame-loader
    implementation in Google Chrome allows remote attackers
    to cause a denial of service or possibly have
    unspecified other impact via unknown vectors.

  - CVE-2011-1293
    Use-after-free vulnerability in the HTMLCollection
    implementation in Google Chrome allows remote attackers
    to cause a denial of service or possibly have
    unspecified other impact via unknown vectors.

  - CVE-2011-1440
    Use-after-free vulnerability in Google Chrome allows
    remote attackers to cause a denial of service or
    possibly have unspecified other impact via vectors
    related to the Ruby element and Cascading Style Sheets
    (CSS) token sequences.

  - CVE-2011-1444
    Race condition in the sandbox launcher implementation in
    Google Chrome on Linux allows remote attackers to cause
    a denial of service or possibly have unspecified other
    impact via unknown vectors.

  - CVE-2011-1797
    Google Chrome does not properly render tables, which
    allows remote attackers to cause a denial of service or
    possibly have unspecified other impact via unknown
    vectors that lead to a 'stale pointer'.

  - CVE-2011-1799
    Google Chrome does not properly perform casts of
    variables during interaction with the WebKit engine,
    which allows remote attackers to cause a denial of
    service or possibly have unspecified other impact via
    unknown vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1292"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1293"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1440"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1444"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1797"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1799"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2245"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (squeeze), these problems have been fixed
in version 6.0.472.63~r59945-5+squeeze5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/05/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/06/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"chromium-browser", reference:"6.0.472.63~r59945-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-dbg", reference:"6.0.472.63~r59945-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-inspector", reference:"6.0.472.63~r59945-5+squeeze5")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-l10n", reference:"6.0.472.63~r59945-5+squeeze5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
