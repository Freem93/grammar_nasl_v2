#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2273. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55524);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/19 17:45:43 $");

  script_cve_id("CVE-2011-0083", "CVE-2011-0085", "CVE-2011-2362", "CVE-2011-2363", "CVE-2011-2365", "CVE-2011-2371", "CVE-2011-2373", "CVE-2011-2374", "CVE-2011-2376");
  script_bugtraq_id(48357, 48358, 48360, 48361, 48366, 48368, 48372, 48373, 48376);
  script_osvdb_id(73177, 73179, 73181, 73182, 73184, 73185, 73186, 73187, 73188);
  script_xref(name:"DSA", value:"2273");

  script_name(english:"Debian DSA-2273-1 : icedove - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Icedove, an unbranded
version of the Thunderbird mail/news client.

  - CVE-2011-0083 / CVE-2011-2363
    'regenrecht' discovered two use-after-frees in SVG
    processing, which could lead to the execution of
    arbitrary code.

  - CVE-2011-0085
    'regenrecht' discovered a use-after-free in XUL
    processing, which could lead to the execution of
    arbitrary code.

  - CVE-2011-2362
    David Chan discovered that cookies were insufficiently
    isolated.

  - CVE-2011-2371
    Chris Rohlf and Yan Ivnitskiy discovered an integer
    overflow in the JavaScript engine, which could lead to
    the execution of arbitrary code.

  - CVE-2011-2373
    Martin Barbella discovered a use-after-free in XUL
    processing, which could lead to the execution of
    arbitrary code.

  - CVE-2011-2374
    Bob Clary, Kevin Brosnan, Nils, Gary Kwong, Jesse
    Ruderman and Christian Biesinger discovered memory
    corruption bugs, which may lead to the execution of
    arbitrary code.

  - CVE-2011-2376
    Luke Wagner and Gary Kwong discovered memory corruption
    bugs, which may lead to the execution of arbitrary code.

As indicated in the Lenny (oldstable) release notes, security support
for the Icedove packages in the oldstable needed to be stopped before
the end of the regular Lenny security maintenance life cycle. You are
strongly encouraged to upgrade to stable or switch to a different mail
client."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0085"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2362"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2371"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2373"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2376"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/icedove"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2273"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the icedove packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.0.11-1+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Mozilla Firefox Array.reduceRight() Integer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:icedove");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/07");
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
if (deb_check(release:"6.0", prefix:"icedove", reference:"3.0.11-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dbg", reference:"3.0.11-1+squeeze3")) flag++;
if (deb_check(release:"6.0", prefix:"icedove-dev", reference:"3.0.11-1+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
