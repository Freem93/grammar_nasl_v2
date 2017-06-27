#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-37-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82185);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2016/04/28 18:23:47 $");

  script_cve_id("CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345");
  script_bugtraq_id(68908, 68909, 69159, 69160, 69168);
  script_osvdb_id(108748, 108751, 109389, 109390, 109908);

  script_name(english:"Debian DLA-37-1 : krb5 security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in krb5, the MIT
implementation of Kerberos. The Common Vulnerabilities and Exposures
project identifies the following problems :

CVE-2014-4341

An unauthenticated remote attacker with the ability to inject packets
into a legitimately established GSSAPI application session can cause a
program crash due to invalid memory references when attempting to read
beyond the end of a buffer.

CVE-2014-4342

An unauthenticated remote attacker with the ability to inject packets
into a legitimately established GSSAPI application session can cause a
program crash due to invalid memory references when reading beyond the
end of a buffer or by causing a NULL pointer dereference.

CVE-2014-4343

An unauthenticated remote attacker with the ability to spoof packets
appearing to be from a GSSAPI acceptor can cause a double-free
condition in GSSAPI initiators (clients) which are using the SPNEGO
mechanism, by returning a different underlying mechanism than was
proposed by the initiator. A remote attacker could exploit this flaw
to cause an application crash or potentially execute arbitrary code.

CVE-2014-4344

An unauthenticated or partially authenticated remote attacker can
cause a NULL dereference and application crash during a SPNEGO
negotiation by sending an empty token as the second or later context
token from initiator to acceptor.

CVE-2014-4345

When kadmind is configured to use LDAP for the KDC database, an
authenticated remote attacker can cause it to perform an out-of-bounds
write (buffer overflow).

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/08/msg00012.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/krb5"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
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

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/18");
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
if (deb_check(release:"6.0", prefix:"krb5-admin-server", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-doc", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc-ldap", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-multidev", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-pkinit", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-user", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb5-dev", reference:"1.8.3+dfsg-4squeeze8")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb53", reference:"1.8.3+dfsg-4squeeze8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
