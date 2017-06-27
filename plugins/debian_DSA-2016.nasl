#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2016. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45057);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2013/05/17 23:54:24 $");

  script_osvdb_id(62724, 62725);
  script_xref(name:"DSA", value:"2016");

  script_name(english:"Debian DSA-2016-1 : drupal6 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities (SA-CORE-2010-001) have been discovered in
drupal6, a fully-featured content management framework.

Installation cross site scripting

A user-supplied value is directly output during installation allowing
a malicious user to craft a URL and perform a cross-site scripting
attack. The exploit can only be conducted on sites not yet installed.

Open redirection

The API function drupal_goto() is susceptible to a phishing attack. An
attacker could formulate a redirect in a way that gets the Drupal site
to send the user to an arbitrarily provided URL. No user submitted
data will be sent to that URL.

Locale module cross site scripting

Locale module and dependent contributed modules do not sanitize the
display of language codes, native and English language names properly.
While these usually come from a preselected list, arbitrary
administrator input is allowed. This vulnerability is mitigated by the
fact that the attacker must have a role with the 'administer
languages' permission.

Blocked user session regeneration

Under certain circumstances, a user with an open session that is
blocked can maintain his/her session on the Drupal site, despite being
blocked."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=572439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2016"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the drupal6 package.

For the stable distribution (lenny), these problems have been fixed in
version 6.6-3lenny5."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:drupal6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"drupal6", reference:"6.6-3lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
