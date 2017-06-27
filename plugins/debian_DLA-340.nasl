#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-340-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86793);
  script_version("$Revision: 2.4 $");
  script_cvs_date("$Date: 2016/04/28 18:15:20 $");

  script_cve_id("CVE-2015-2695", "CVE-2015-2697");
  script_osvdb_id(129480, 129481);

  script_name(english:"Debian DLA-340-1 : krb5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2015-2695

It was discovered that applications which call gss_inquire_context()
on a partially-established SPNEGO context can cause the GSS-API
library to read from a pointer using the wrong type, leading to a
process crash.

CVE-2015-2697

It was discovered that the build_principal_va() function incorrectly
handles input strings. An authenticated attacker can take advantage of
this flaw to cause a KDC to crash using a TGS request with a large
realm field beginning with a null byte.

For the oldoldstable distribution (squeeze), these problems have been
fixed in version 1.8.3+dfsg-4squeeze10.

We recommend that you upgrade your krb5 packages.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/11/msg00001.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/krb5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-admin-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-kdc-ldap");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-multidev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-pkinit");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-user");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb5-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libkrb53");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/09");
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
if (deb_check(release:"6.0", prefix:"krb5-admin-server", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-doc", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc-ldap", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-multidev", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-pkinit", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-user", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb5-dev", reference:"1.8.3+dfsg-4squeeze10")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb53", reference:"1.8.3+dfsg-4squeeze10")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
