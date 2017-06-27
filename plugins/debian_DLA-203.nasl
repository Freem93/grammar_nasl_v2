#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-203-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82861);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:16 $");

  script_name(english:"Debian DLA-203-1 : openldap security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were found in OpenLDAP, a free implementation
of the Lightweight Directory Access Protocol.

Please carefully check whether you are affected by CVE-2014-9713: if
you are, you will need to manually upgrade your configuration! See
below for more details on this. Just upgrading the packages might not
be enough!

CVE-2012-1164

Fix a crash when doing an attrsOnly search of a database configured
with both the rwm and translucent overlays.

CVE-2013-4449

Michael Vishchers from Seven Principles AG discovered a denial of
service vulnerability in slapd, the directory server implementation.
When the server is configured to used the RWM overlay, an attacker can
make it crash by unbinding just after connecting, because of an issue
with reference counting.

CVE-2014-9713

The default Debian configuration of the directory database allows
every users to edit their own attributes. When LDAP directories are
used for access control, and this is done using user attributes, an
authenticated user can leverage this to gain access to unauthorized
resources. . Please note this is a Debian specific vulnerability. .
The new package won't use the unsafe access control rule for new
databases, but existing configurations won't be automatically
modified. Administrators are incited to look at the README.Debian file
provided by the updated package if they need to fix the access control
rule.

CVE-2015-1545

Ryan Tandy discovered a denial of service vulnerability in slapd. When
using the deref overlay, providing an empty attribute list in a query
makes the daemon crashes.

Thanks to Ryan Tandy for preparing this update.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/04/msg00016.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openldap"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap-2.4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap-2.4-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd-smbk5pwd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/20");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"ldap-utils", reference:"2.4.23-7.3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libldap-2.4-2", reference:"2.4.23-7.3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libldap-2.4-2-dbg", reference:"2.4.23-7.3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libldap2-dev", reference:"2.4.23-7.3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"slapd", reference:"2.4.23-7.3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"slapd-dbg", reference:"2.4.23-7.3+deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"slapd-smbk5pwd", reference:"2.4.23-7.3+deb6u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
