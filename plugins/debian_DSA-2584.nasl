#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2584. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63194);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-4201", "CVE-2012-4207", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5842");
  script_osvdb_id(87587, 87594, 87596, 87608, 87609);
  script_xref(name:"DSA", value:"2584");

  script_name(english:"Debian DSA-2584-1 : iceape - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in Iceape, the Debian
Internet suite based on Mozilla SeaMonkey :

  - CVE-2012-5829
    Heap-based buffer overflow in the
    nsWindow::OnExposeEvent function could allow remote
    attackers to execute arbitrary code.

  - CVE-2012-5842
    Multiple unspecified vulnerabilities in the browser
    engine could allow remote attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly execute arbitrary code.

  - CVE-2012-4207
    The HZ-GB-2312 character-set implementation does not
    properly handle a ~ (tilde) character in proximity to a
    chunk delimiter, which allows remote attackers to
    conduct cross-site scripting (XSS) attacks via a crafted
    document.

  - CVE-2012-4201
    The evalInSandbox implementation uses an incorrect
    context during the handling of JavaScript code that sets
    the location.href property, which allows remote
    attackers to conduct cross-site scripting (XSS) attacks
    or read arbitrary files by leveraging a sandboxed
    add-on.

  - CVE-2012-4216
    Use-after-free vulnerability in the
    gfxFont::GetFontEntry function allows remote attackers
    to execute arbitrary code or cause a denial of service
    (heap memory corruption) via unspecified vectors."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-5842"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4216"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceape"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2584"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceape packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.0.11-17."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceape");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"iceape", reference:"2.0.11-17")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-browser", reference:"2.0.11-17")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-chatzilla", reference:"2.0.11-17")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dbg", reference:"2.0.11-17")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-dev", reference:"2.0.11-17")) flag++;
if (deb_check(release:"6.0", prefix:"iceape-mailnews", reference:"2.0.11-17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
