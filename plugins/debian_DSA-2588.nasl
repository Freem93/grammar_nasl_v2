#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2588. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63272);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-4201", "CVE-2012-4207", "CVE-2012-4216", "CVE-2012-5829", "CVE-2012-5842");
  script_bugtraq_id(56611, 56618, 56632, 56634, 56636);
  script_osvdb_id(87587, 87594, 87596, 87608, 87609);
  script_xref(name:"DSA", value:"2588");

  script_name(english:"Debian DSA-2588-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in Icedove, Debian's version
of the Mozilla Thunderbird mail and news client.

  - CVE-2012-4201
    The evalInSandbox implementation uses an incorrect
    context during the handling of JavaScript code that sets
    the location.href property, which allows remote
    attackers to conduct cross-site scripting (XSS) attacks
    or read arbitrary files by leveraging a sandboxed
    add-on.

  - CVE-2012-4207
    The HZ-GB-2312 character-set implementation does not
    properly handle a ~ (tilde) character in proximity to a
    chunk delimiter, which allows remote attackers to
    conduct cross-site scripting (XSS) attacks via a crafted
    document.

  - CVE-2012-4216
    Use-after-free vulnerability in the
    gfxFont::GetFontEntry function allows remote attackers
    to execute arbitrary code or cause a denial of service
    (heap memory corruption) via unspecified vectors.

  - CVE-2012-5829
    Heap-based buffer overflow in the
    nsWindow::OnExposeEvent function could allow remote
    attackers to execute arbitrary code.

  - CVE-2012-5842
    Multiple unspecified vulnerabilities in the browser
    engine could allow remote attackers to cause a denial of
    service (memory corruption and application crash) or
    possibly execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4207"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4216"
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
    value:"https://packages.debian.org/source/squeeze/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2588"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (squeeze), these problems have been fixed
in version 3.0.11-1+squeeze15."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/12/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/12/17");
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
if (deb_check(release:"6.0", prefix:"icedove", reference:"3.0.11-1+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dbg", reference:"3.0.11-1+squeeze15")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dev", reference:"3.0.11-1+squeeze15")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
