#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2934. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(74097);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2014-0472", "CVE-2014-0473", "CVE-2014-0474", "CVE-2014-1418", "CVE-2014-3730");
  script_bugtraq_id(67038, 67040, 67041, 67408, 67410);
  script_osvdb_id(107011, 107012);
  script_xref(name:"DSA", value:"2934");

  script_name(english:"Debian DSA-2934-1 : python-django - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in Django, a high-level Python
web development framework. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2014-0472
    Benjamin Bach discovered that Django incorrectly handled
    dotted Python paths when using the reverse() URL
    resolver function. An attacker able to request a
    specially crafted view from a Django application could
    use this issue to cause Django to import arbitrary
    modules from the Python path, resulting in possible code
    execution.

  - CVE-2014-0473
    Paul McMillan discovered that Django incorrectly cached
    certain pages that contained CSRF cookies. A remote
    attacker could use this flaw to acquire the CSRF token
    of a different user and bypass intended CSRF protections
    in a Django application.

  - CVE-2014-0474
    Michael Koziarski discovered that certain Django model
    field classes did not properly perform type conversion
    on their arguments, which allows remote attackers to
    obtain unexpected results.

  - CVE-2014-1418
    Michael Nelson, Natalia Bidart and James Westby
    discovered that cached data in Django could be served to
    a different session, or to a user with no session at
    all. An attacker may use this to retrieve private data
    or poison caches.

  - CVE-2014-3730
    Peter Kuma and Gavin Wahl discovered that Django
    incorrectly validated certain malformed URLs from user
    input. An attacker may use this to cause unexpected
    redirects."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0472"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0473"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-0474"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-1418"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-3730"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/python-django"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-2934"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the python-django packages.

For the oldstable distribution (squeeze), these problems have been
fixed in version 1.2.3-3+squeeze10.

For the stable distribution (wheezy), these problems have been fixed
in version 1.4.5-1+deb7u7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:python-django");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"python-django", reference:"1.2.3-3+squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"python-django-doc", reference:"1.2.3-3+squeeze10")) flag++;
if (deb_check(release:"7.0", prefix:"python-django", reference:"1.4.5-1+deb7u7")) flag++;
if (deb_check(release:"7.0", prefix:"python-django-doc", reference:"1.4.5-1+deb7u7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
