#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1195. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22881);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-2940", "CVE-2006-3738", "CVE-2006-4343");
  script_bugtraq_id(20246, 20247, 20249);
  script_osvdb_id(29261, 29262, 29263);
  script_xref(name:"DSA", value:"1195");

  script_name(english:"Debian DSA-1195-1 : openssl096 - denial of service (multiple)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in the OpenSSL
cryptographic software package that could allow an attacker to launch
a denial of service attack by exhausting system resources or crashing
processes on a victim's computer.

  - CVE-2006-3738
    Tavis Ormandy and Will Drewry of the Google Security
    Team discovered a buffer overflow in
    SSL_get_shared_ciphers utility function, used by some
    applications such as exim and mysql. An attacker could
    send a list of ciphers that would overrun a buffer.

  - CVE-2006-4343
    Tavis Ormandy and Will Drewry of the Google Security
    Team discovered a possible DoS in the sslv2 client code.
    Where a client application uses OpenSSL to make a SSLv2
    connection to a malicious server that server could cause
    the client to crash.

  - CVE-2006-2940
    Dr S N Henson of the OpenSSL core team and Open Network
    Security recently developed an ASN1 test suite for NISCC
    ( www.niscc.gov.uk). When the test suite was run against
    OpenSSL a DoS was discovered.

  Certain types of public key can take disproportionate amounts of
  time to process. This could be used by an attacker in a denial of
  service attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3738"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-2940"
  );
  # http://www.niscc.gov.uk/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.cpni.gov.uk/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1195"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl096 package. Note that services linking against the
openssl shared libraries will need to be restarted. Common examples of
such services include most Mail Transport Agents, SSH servers, and web
servers.

For the stable distribution (sarge) these problems have been fixed in
version 0.9.6m-1sarge4.

This package exists only for compatibility with older software, and is
not present in the unstable or testing branches of Debian."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl096");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/20");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libssl0.9.6", reference:"0.9.6m-1sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
