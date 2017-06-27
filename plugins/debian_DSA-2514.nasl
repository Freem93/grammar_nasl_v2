#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2514. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(60005);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2012-1948", "CVE-2012-1950", "CVE-2012-1954", "CVE-2012-1966", "CVE-2012-1967");
  script_osvdb_id(83995, 84007, 84008, 84009, 84013);
  script_xref(name:"DSA", value:"2514");

  script_name(english:"Debian DSA-2514-1 : iceweasel - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Iceweasel, a web
browser based on Firefox. The included XULRunner library provides
rendering services for several other applications included in Debian.

  - CVE-2012-1948
    Benoit Jacob, Jesse Ruderman, Christian Holler, and Bill
    McCloskey identified several memory safety problems that
    may lead to the execution of arbitrary code.

  - CVE-2012-1950
    Mario Gomes and Code Audit Labs discovered that it is
    possible to force Iceweasel to display the URL of the
    previous entered site through drag and drop actions to
    the address bar. This can be abused to perform phishing
    attacks.

  - CVE-2012-1954
    Abhishek Arya discovered a use-after-free problem in
    nsDocument::AdoptNode that may lead to the execution of
    arbitrary code.

  - CVE-2012-1966
    'moz_bug_r_a4' discovered that it is possible to perform
    cross-site scripting attacks through the context menu
    when using data: URLs.

  - CVE-2012-1967
    'moz_bug_r_a4' discovered that in certain cases,
    javascript: URLs can be executed so that scripts can
    escape the JavaScript sandbox and run with elevated
    privileges.

Note: We'd like to advise users of Iceweasel's 3.5 branch in Debian
stable to consider to upgrade to the Iceweasel 10.0 ESR (Extended
Support Release) which is now available in Debian Backports. Although
Debian will continue to support Iceweasel 3.5 in stable with security
updates, this can only be done on a best effort basis as upstream
provides no such support anymore. On top of that, the 10.0 branch adds
proactive security features to the browser."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1954"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1966"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1967"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2514"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-17."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"iceweasel", reference:"3.5.16-17")) flag++;
if (deb_check(release:"6.0", prefix:"iceweasel-dbg", reference:"3.5.16-17")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
