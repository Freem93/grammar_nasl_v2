#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-146-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82129);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 14:49:54 $");

  script_cve_id("CVE-2014-5352", "CVE-2014-9421", "CVE-2014-9422", "CVE-2014-9423");
  script_bugtraq_id(72494, 72495, 72496, 72503);
  script_osvdb_id(117920, 117921, 117922, 117923);

  script_name(english:"Debian DLA-146-1 : krb5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiples vulnerabilities have been found in krb5, the MIT
implementation of Kerberos :

CVE-2014-5352

Incorrect memory management in the libgssapi_krb5 library might result
in denial of service or the execution of arbitrary code.

CVE-2014-9421

Incorrect memory management in kadmind's processing of XDR data might
result in denial of service or the execution of arbitrary code.

CVE-2014-9422

Incorrect processing of two-component server principals might result
in impersonation attacks.

CVE-2014-9423

An information leak in the libgssrpc library.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2015/02/msg00002.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/krb5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2015/02/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"krb5-admin-server", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-doc", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc-ldap", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-multidev", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-pkinit", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-user", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb5-dev", reference:"1.8.3+dfsg-4squeeze9")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb53", reference:"1.8.3+dfsg-4squeeze9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
