#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Debian Security Advisory DLA-81-1. The text
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82226);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2015/12/02 20:16:13 $");

  script_cve_id("CVE-2014-3567", "CVE-2014-3568", "CVE-2014-3569");
  script_bugtraq_id(70585, 70586, 71934);
  script_osvdb_id(113374, 113377, 116423);

  script_name(english:"Debian DLA-81-1 : openssl security update");
  script_summary(english:"Checks dpkg output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in OpenSSL.

CVE-2014-3566 ('POODLE')

A flaw was found in the way SSL 3.0 handled padding bytes when
decrypting messages encrypted using block ciphers in cipher block
chaining (CBC) mode. This flaw allows a man-in-the-middle (MITM)
attacker to decrypt a selected byte of a cipher text in as few as 256
tries if they are able to force a victim application to repeatedly
send the same data over newly created SSL 3.0 connections. 

This update adds support for Fallback SCSV to mitigate this issue.
This does not fix the issue. The proper way to fix this is to disable
SSL 3.0.

CVE-2014-3567

A memory leak flaw was found in the way an OpenSSL handled failed
session ticket integrity checks. A remote attacker could exhaust all
available memory of an SSL/TLS or DTLS server by sending a large
number of invalid session tickets to that server.

CVE-2014-3568

When OpenSSL is configured with 'no-ssl3' as a build option, servers
could accept and complete a SSL 3.0 handshake, and clients could be
configured to send them.

Note that the package is Debian is not build with this option.

CVE-2014-3569

When openssl is build with the no-ssl3 option and a SSL v3 Client
Hello is received the ssl method would be set to NULL which could
later result in a NULL pointer dereference.

Note that the package is Debian is not build with this option.

NOTE: Tenable Network Security has extracted the preceding description
block directly from the DLA security advisory. Tenable has attempted
to automatically clean and format it as much as possible without
introducing additional issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://lists.debian.org/debian-lts-announce/2014/11/msg00000.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze-lts/openssl"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libcrypto0.9.8-udeb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl-dev");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl0.9.8");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libssl0.9.8-dbg");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/26");
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
if (deb_check(release:"6.0", prefix:"libcrypto0.9.8-udeb", reference:"0.9.8o-4squeeze18")) flag++;
if (deb_check(release:"6.0", prefix:"libssl-dev", reference:"0.9.8o-4squeeze18")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8", reference:"0.9.8o-4squeeze18")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8o-4squeeze18")) flag++;
if (deb_check(release:"6.0", prefix:"openssl", reference:"0.9.8o-4squeeze18")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
