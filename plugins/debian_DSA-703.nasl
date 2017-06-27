#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-703. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(17674);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-0468", "CVE-2005-0469");
  script_osvdb_id(15093, 15094);
  script_xref(name:"CERT", value:"291924");
  script_xref(name:"CERT", value:"341908");
  script_xref(name:"DSA", value:"703");

  script_name(english:"Debian DSA-703-1 : krb5 - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in telnet clients that could be
exploited by malicious daemons the client connects to. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2005-0468
    Gael Delalleau discovered a buffer overflow in the
    env_opt_add() function that allow a remote attacker to
    execute arbitrary code.

  - CAN-2005-0469

    Gael Delalleau discovered a buffer overflow in the
    handling of the LINEMODE suboptions in telnet clients.
    This can lead to the execution of arbitrary code when
    connected to a malicious server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-703"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 package.

For the stable distribution (woody) these problems have been fixed in
version 1.2.4-5woody8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/04/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/04/02");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/03/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"krb5-admin-server", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-clients", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-doc", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-ftpd", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-kdc", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-rsh-server", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-telnetd", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-user", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm55", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-dev", reference:"1.2.4-5woody8")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb53", reference:"1.2.4-5woody8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");