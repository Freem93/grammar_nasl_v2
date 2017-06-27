#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2115. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(49717);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-1613", "CVE-2010-1614", "CVE-2010-1615", "CVE-2010-1616", "CVE-2010-1617", "CVE-2010-1618", "CVE-2010-1619", "CVE-2010-2228", "CVE-2010-2229", "CVE-2010-2230", "CVE-2010-2231");
  script_bugtraq_id(39150, 40944);
  script_xref(name:"DSA", value:"2115");

  script_name(english:"Debian DSA-2115-1 : moodle - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in Moodle, a
course management system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2010-1613
    Moodle does not enable the 'Regenerate session id during
    login' setting by default, which makes it easier for
    remote attackers to conduct session fixation attacks.

  - CVE-2010-1614
    Multiple cross-site scripting (XSS) vulnerabilities
    allow remote attackers to inject arbitrary web script or
    HTML via vectors related to (1) the Login-As feature or
    (2) when the global search feature is enabled,
    unspecified global search forms in the Global Search
    Engine.

  - CVE-2010-1615
    Multiple SQL injection vulnerabilities allow remote
    attackers to execute arbitrary SQL commands via vectors
    related to (1) the add_to_log function in
    mod/wiki/view.php in the wiki module, or (2) 'data
    validation in some forms elements' related to
    lib/form/selectgroups.php.

  - CVE-2010-1616
    Moodle can create new roles when restoring a course,
    which allows teachers to create new accounts even if
    they do not have the moodle/user:create capability.

  - CVE-2010-1617
    user/view.php does not properly check a role, which
    allows remote authenticated users to obtain the full
    names of other users via the course profile page.

  - CVE-2010-1618
    A Cross-site scripting (XSS) vulnerability in the phpCAS
    client library allows remote attackers to inject
    arbitrary web script or HTML via a crafted URL, which is
    not properly handled in an error message.

  - CVE-2010-1619
    A Cross-site scripting (XSS) vulnerability in the
    fix_non_standard_entities function in the KSES HTML text
    cleaning library (weblib.php) allows remote attackers to
    inject arbitrary web script or HTML via crafted HTML
    entities.

  - CVE-2010-2228
    A Cross-site scripting (XSS) vulnerability in the MNET
    access-control interface allows remote attackers to
    inject arbitrary web script or HTML via vectors
    involving extended characters in a username.

  - CVE-2010-2229
    Multiple cross-site scripting (XSS) vulnerabilities in
    blog/index.php allow remote attackers to inject
    arbitrary web script or HTML via unspecified parameters.

  - CVE-2010-2230
    The KSES text cleaning filter in lib/weblib.php does not
    properly handle vbscript URIs, which allows remote
    authenticated users to conduct cross-site scripting
    (XSS) attacks via HTML input.

  - CVE-2010-2231
    A Cross-site request forgery (CSRF) vulnerability in
    report/overview/report.php in the quiz module allows
    remote attackers to hijack the authentication of
    arbitrary users for requests that delete quiz attempts
    via the attemptid parameter."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1613"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1615"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1616"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-1619"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2228"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2229"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2230"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2231"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2115"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moodle package.

This security update switches to a new upstream version and requires
database updates. After installing the fixed package, you must visit
<http://localhost/moodle/admin/> and follow the update instructions.

For the stable distribution (lenny), these problems have been fixed in
version 1.8.13-1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/09/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/10/06");
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
if (deb_check(release:"5.0", prefix:"moodle", reference:"1.8.13-1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
