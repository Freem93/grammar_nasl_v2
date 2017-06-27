#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1125. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22667);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2006-2742", "CVE-2006-2743", "CVE-2006-2831", "CVE-2006-2832", "CVE-2006-2833");
  script_osvdb_id(25908, 25909, 25910, 25911, 27592, 27593, 27595);
  script_xref(name:"DSA", value:"1125");

  script_name(english:"Debian DSA-1125-2 : drupal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Drupal update in DSA 1125 contained a regression. This update
corrects this flaw. For completeness, the original advisory text below
:

Several remote vulnerabilities have been discovered in the Drupal
website platform, which may lead to the execution of arbitrary web
script. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2006-2742
    A SQL injection vulnerability has been discovered in the
    'count' and 'from' variables of the database interface.

  - CVE-2006-2743
    Multiple file extensions were handled incorrectly if
    Drupal ran on Apache with mod_mime enabled.

  - CVE-2006-2831
    A variation of CVE-2006-2743 was addressed as well.

  - CVE-2006-2832
    A Cross-Site-Scripting vulnerability in the upload
    module has been discovered.

  - CVE-2006-2833
    A Cross-Site-Scripting vulnerability in the taxonomy
    module has been discovered."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=368835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2742"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2743"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2833"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1125"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the drupal packages.

For the stable distribution (sarge) these problems have been fixed in
version 4.5.3-6.1sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:drupal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"drupal", reference:"4.5.3-6.1sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
