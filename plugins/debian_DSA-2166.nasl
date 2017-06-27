#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2166. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52029);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-0777", "CVE-2011-0778", "CVE-2011-0783", "CVE-2011-0981", "CVE-2011-0983", "CVE-2011-0984", "CVE-2011-0985");
  script_bugtraq_id(46144, 46262);
  script_osvdb_id(70977, 70978, 70979, 70980, 70983, 70990, 75255);
  script_xref(name:"DSA", value:"2166");

  script_name(english:"Debian DSA-2166-1 : chromium-browser - several vulnerabilities");
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

  - CVE-2011-0777
    Use-after-free vulnerability in Google Chrome before
    9.0.597.84 allows remote attackers to cause a denial of
    service or possibly have unspecified other impact via
    vectors related to image loading.

  - CVE-2011-0778
    Google Chrome before 9.0.597.84 does not properly
    restrict drag and drop operations, which might allow
    remote attackers to bypass the Same Origin Policy via
    unspecified vectors.

  - CVE-2011-0783
    Unspecified vulnerability in Google Chrome before
    9.0.597.84 allows user-assisted remote attackers to
    cause a denial of service (application crash) via
    vectors involving a 'bad volume setting'.

  - CVE-2011-0983
    Google Chrome before 9.0.597.94 does not properly handle
    anonymous blocks, which allows remote attackers to cause
    a denial of service or possibly have unspecified other
    impact via unknown vectors that lead to a 'stale
    pointer'.

  - CVE-2011-0981
    Google Chrome before 9.0.597.94 does not properly
    perform event handling for animations, which allows
    remote attackers to cause a denial of service or
    possibly have unspecified other impact via unknown
    vectors that lead to a'stale pointer'.

  - CVE-2011-0984
    Google Chrome before 9.0.597.94 does not properly handle
    plug-ins, which allows remote attackers to cause a
    denial of service (out-of-bounds read) via unspecified
    vectors.

  - CVE-2011-0985
    Google Chrome before 9.0.597.94 does not properly
    perform process termination upon memory exhaustion,
    which has unspecified impact and remote attack vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0777"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0778"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0783"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0983"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0981"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0984"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0985"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/chromium-browser"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2166"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the chromium-browser packages.

For the stable distribution (squeeze), these problems have been fixed
in version 6.0.472.63~r59945-5+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:chromium-browser");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/20");
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
if (deb_check(release:"6.0", prefix:"chromium-browser", reference:"6.0.472.63~r59945-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-dbg", reference:"6.0.472.63~r59945-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-inspector", reference:"6.0.472.63~r59945-5+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"chromium-browser-l10n", reference:"6.0.472.63~r59945-5+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
