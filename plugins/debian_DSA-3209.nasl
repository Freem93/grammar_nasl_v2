#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3209. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82432);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2013-4449", "CVE-2014-9713", "CVE-2015-1545");
  script_bugtraq_id(63190, 72519);
  script_osvdb_id(98656, 118031, 120147);
  script_xref(name:"DSA", value:"3209");

  script_name(english:"Debian DSA-3209-1 : openldap - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in OpenLDAP, a free implementation
of the Lightweight Directory Access Protocol.

  - CVE-2013-4449
    Michael Vishchers from Seven Principles AG discovered a
    denial of service vulnerability in slapd, the directory
    server implementation. When the server is configured to
    used the RWM overlay, an attacker can make it crash by
    unbinding just after connecting, because of an issue
    with reference counting.

  - CVE-2014-9713
    The default Debian configuration of the directory
    database allows every users to edit their own
    attributes. When LDAP directories are used for access
    control, and this is done using user attributes, an
    authenticated user can leverage this to gain access to
    unauthorized resources.

  Please note this is a Debian specific vulnerability.

  The new package won't use the unsafe access control rule for new
  databases, but existing configurations won't be automatically
  modified. Administrators are incited to look at the README.Debian
  file provided by the updated package if they need to fix the access
  control rule.

  - CVE-2015-1545
    Ryan Tandy discovered a denial of service vulnerability
    in slapd. When using the deref overlay, providing an
    empty attribute list in a query makes the daemon
    crashes."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=729367"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=761406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=776988"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4449"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-9713"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-1545"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/openldap"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3209"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openldap packages.

For the stable distribution (wheezy), these problems have been fixed
in version 2.4.31-2.

For the upcoming stable distribution (jessie), these problems have
been fixed in version 2.4.40-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openldap");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"ldap-utils", reference:"2.4.31-2")) flag++;
if (deb_check(release:"7.0", prefix:"libldap-2.4-2", reference:"2.4.31-2")) flag++;
if (deb_check(release:"7.0", prefix:"libldap-2.4-2-dbg", reference:"2.4.31-2")) flag++;
if (deb_check(release:"7.0", prefix:"libldap2-dev", reference:"2.4.31-2")) flag++;
if (deb_check(release:"7.0", prefix:"slapd", reference:"2.4.31-2")) flag++;
if (deb_check(release:"7.0", prefix:"slapd-dbg", reference:"2.4.31-2")) flag++;
if (deb_check(release:"7.0", prefix:"slapd-smbk5pwd", reference:"2.4.31-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
