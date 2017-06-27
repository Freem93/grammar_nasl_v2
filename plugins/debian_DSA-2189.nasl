#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2189. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52621);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-1108", "CVE-2011-1109", "CVE-2011-1113", "CVE-2011-1114", "CVE-2011-1115", "CVE-2011-1121", "CVE-2011-1122");
  script_bugtraq_id(46614);
  script_osvdb_id(72271, 72272, 72278, 72279, 72280, 72284, 72285);
  script_xref(name:"DSA", value:"2189");

  script_name(english:"Debian DSA-2189-1 : chromium-browser - several vulnerabilities");
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

  - CVE-2011-1108
    Google Chrome before 9.0.597.107 does not properly
    implement JavaScript dialogs, which allows remote
    attackers to cause a denial of service (application
    crash) or possibly have unspecified other impact via a
    crafted HTML document.

  - CVE-2011-1109
    Google Chrome before 9.0.597.107 does not properly
    process nodes in Cascading Style Sheets (CSS)
    stylesheets, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via unknown vectors that lead to a 'stale
    pointer'.

  - CVE-2011-1113
    Google Chrome before 9.0.597.107 on 64-bit Linux
    platforms does not properly perform pickle
    deserialization, which allows remote attackers to cause
    a denial of service (out-of-bounds read) via unspecified
    vectors.

  - CVE-2011-1114
    Google Chrome before 9.0.597.107 does not properly
    handle tables, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via unknown vectors that lead to a 'stale node'.

  - CVE-2011-1115
    Google Chrome before 9.0.597.107 does not properly
    render tables, which allows remote attackers to cause a
    denial of service or possibly have unspecified other
    impact via unknown vectors that lead to a 'stale
    pointer'.

  - CVE-2011-1121
    Integer overflow in Google Chrome before 9.0.597.107
    allows remote attackers to cause a denial of service or
    possibly have unspecified other impact via vectors
    involving a TEXTAREA element.

  - CVE-2011-1122
    The WebGL implementation in Google Chrome before
    9.0.597.107 allows remote attackers to cause a denial of
    service (out-of-bounds read) via unspecified vectors,
    aka Issue 71960.

  - In addition, this upload fixes the following issues
    (they don't have a CVE id yet) :

    - Out-of-bounds read in text searching. [69640]
    - Memory corruption in SVG fonts. [72134]

    - Memory corruption with counter nodes. [69628]

    - Stale node in box layout. [70027]

    - Cross-origin error message leak with workers. [70336]

    - Stale pointer in table painting. [72028]

    - Stale pointer with SVG cursors. [73746]"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1108"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1109"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1114"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1121"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1122"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2189"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (squeeze), these problems have been fixed
in version 6.0.472.63~r59945-5+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/11");
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
if (deb_check(release:"6.0", prefix:"chromium-browser", reference:"6.0.472.63~r59945-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-dbg", reference:"6.0.472.63~r59945-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-inspector", reference:"6.0.472.63~r59945-5+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-l10n", reference:"6.0.472.63~r59945-5+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
