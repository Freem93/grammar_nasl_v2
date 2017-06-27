#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2124. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50453);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2010-3174", "CVE-2010-3176", "CVE-2010-3177", "CVE-2010-3178", "CVE-2010-3179", "CVE-2010-3180", "CVE-2010-3183", "CVE-2010-3765");
  script_bugtraq_id(44246, 44253);
  script_xref(name:"DSA", value:"2124");

  script_name(english:"Debian DSA-2124-1 : xulrunner - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Xulrunner, the
component that provides the core functionality of Iceweasel, Debian's
variant of Mozilla's browser technology.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2010-3765
    Xulrunner allows remote attackers to execute arbitrary
    code via vectors related to
    nsCSSFrameConstructor::ContentAppended, the appendChild
    method, incorrect index tracking, and the creation of
    multiple frames, which triggers memory corruption.

  - CVE-2010-3174 CVE-2010-3176
    Multiple unspecified vulnerabilities in the browser
    engine in Xulrunner allow remote attackers to cause a
    denial of service (memory corruption and application
    crash) or possibly execute arbitrary code via unknown
    vectors.

  - CVE-2010-3177
    Multiple cross-site scripting (XSS) vulnerabilities in
    the Gopher parser in Xulrunner allow remote attackers to
    inject arbitrary web script or HTML via a crafted name
    of a (1) file or (2) directory on a Gopher server.

  - CVE-2010-3178
    Xulrunner does not properly handle certain modal calls
    made by javascript: URLs in circumstances related to
    opening a new window and performing cross-domain
    navigation, which allows remote attackers to bypass the
    Same Origin Policy via a crafted HTML document.

  - CVE-2010-3179
    Stack-based buffer overflow in the text-rendering
    functionality in Xulrunner allows remote attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption and application crash) via a long
    argument to the document.write method.

  - CVE-2010-3180
    Use-after-free vulnerability in the nsBarProp function
    in Xulrunner allows remote attackers to execute
    arbitrary code by accessing the locationbar property of
    a closed window.

  - CVE-2010-3183
    The LookupGetterOrSetter function in Xulrunner does not
    properly support window.__lookupGetter__ function calls
    that lack arguments, which allows remote attackers to
    execute arbitrary code or cause a denial of service
    (incorrect pointer dereference and application crash)
    via a crafted HTML document.

In addition, this security update includes corrections for regressions
caused by the fixes for CVE-2010-0654 and CVE-2010-2769 in DSA-2075-1
and DSA-2106-1."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3765"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3174"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3176"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3177"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3178"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3179"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3180"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3183"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0654"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2124"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Xulrunner packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.9.0.19-6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Interleaved document.write/appendChild Memory Corruption');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xulrunner");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libmozillainterfaces-java", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs-dev", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"libmozjs1d-dbg", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"python-xpcom", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"spidermonkey-bin", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-dbg", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-1.9-gnome-support", reference:"1.9.0.19-6")) flag++;
if (deb_check(release:"5.0", prefix:"xulrunner-dev", reference:"1.9.0.19-6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
