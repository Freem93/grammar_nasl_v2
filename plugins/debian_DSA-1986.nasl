#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1986. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44850);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-4297", "CVE-2009-4298", "CVE-2009-4299", "CVE-2009-4301", "CVE-2009-4302", "CVE-2009-4303", "CVE-2009-4305");
  script_osvdb_id(60814, 60815, 60816, 60817, 60818, 61172, 61173);
  script_xref(name:"DSA", value:"1986");

  script_name(english:"Debian DSA-1986-1 : moodle - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Moodle, an online
course management system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-4297
    Multiple cross-site request forgery (CSRF)
    vulnerabilities have been discovered.

  - CVE-2009-4298
    It has been discovered that the LAMS module is prone to
    the disclosure of user account information.

  - CVE-2009-4299
    The Glossary module has an insufficient access control
    mechanism.

  - CVE-2009-4301
    Moodle does not properly check permissions when the MNET
    service is enabled, which allows remote authenticated
    servers to execute arbitrary MNET functions.

  - CVE-2009-4302
    The login/index_form.html page links to an HTTP page
    instead of using an SSL secured connection.

  - CVE-2009-4303
    Moodle stores sensitive data in backup files, which
    might make it possible for attackers to obtain them.

  - CVE-2009-4305
    It has been discovered that the SCORM module is prone to
    a SQL injection.

Additionally, a SQL injection in the update_record function, a problem
with symbolic links and a verification problem with Glossary, database
and forum ratings have been fixed."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=559531"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4297"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4299"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4301"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4303"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4305"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1986"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moodle packages.

For the stable distribution (lenny), these problems have been fixed in
version 1.8.2.dfsg-3+lenny3.

For the oldstable distribution (etch), there are no fixed packages
available and it is too hard to backport many of the fixes. Therefore,
we recommend to upgrade to the lenny version."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(89, 200, 264, 310, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/02/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"5.0", prefix:"moodle", reference:"1.8.2.dfsg-3+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
