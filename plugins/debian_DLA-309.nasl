#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-309-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85931);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/12/02 20:08:18 $");

  script_cve_id("CVE-2015-6908");
  script_osvdb_id(127342);

  script_name(english:"Debian DLA-309-1 : openldap security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Denis Andzakovic discovered that OpenLDAP, a free implementation of
the Lightweight Directory Access Protocol, does not properly handle
BER data. An unauthenticated remote attacker can use this flaw to
cause a denial of service (slapd daemon crash) via a specially crafted
packet.

The Squeeze-LTS package has been prepared by Ryan Tandy.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/09/msg00005.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openldap"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ldap-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap-2.4-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap-2.4-2-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libldap2-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:slapd-smbk5pwd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/09/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/09/15");
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
if (deb_check(release:"6.0", prefix:"ldap-utils", reference:"2.4.23-7.3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libldap-2.4-2", reference:"2.4.23-7.3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libldap-2.4-2-dbg", reference:"2.4.23-7.3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"libldap2-dev", reference:"2.4.23-7.3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"slapd", reference:"2.4.23-7.3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"slapd-dbg", reference:"2.4.23-7.3+deb6u2")) flag++;
if (deb_check(release:"6.0", prefix:"slapd-smbk5pwd", reference:"2.4.23-7.3+deb6u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
