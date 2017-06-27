#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-136. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14973);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2002-0655", "CVE-2002-0656", "CVE-2002-0657", "CVE-2002-0659", "CVE-2005-1730");
  script_bugtraq_id(5353, 5361, 5362, 5363, 5364, 5366);
  script_osvdb_id(3940, 3942, 3943);
  script_xref(name:"DSA", value:"136");

  script_name(english:"Debian DSA-136-1 : openssl - multiple remote exploits");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The OpenSSL development team has announced that a security audit by
A.L. Digital Ltd and The Bunker, under the DARPA CHATS program, has
revealed remotely exploitable buffer overflow conditions in the
OpenSSL code. Additionally, the ASN1 parser in OpenSSL has a potential
DoS attack independently discovered by Adi Stav and James Yonan.

CAN-2002-0655 references overflows in buffers used to hold ASCII
representations of integers on 64 bit platforms. CAN-2002-0656
references buffer overflows in the SSL2 server implementation (by
sending an invalid key to the server) and the SSL3 client
implementation (by sending a large session id to the client). The SSL2
issue was also noticed by Neohapsis, who have privately demonstrated
exploit code for this issue. CAN-2002-0659 references the ASN1 parser
DoS issue.

These vulnerabilities have been addressed for Debian 3.0 (woody) in
openssl094_0.9.4-6.woody.2, openssl095_0.9.5a-6.woody.1 and
openssl_0.9.6c-2.woody.1.

These vulnerabilities are also present in Debian 2.2 (potato). Fixed
packages are available in openssl094_0.9.4-6.potato.2 and
openssl_0.9.6c-0.potato.4.

A worm is actively exploiting this issue on internet-attached hosts;
we recommend you upgrade your OpenSSL as soon as possible. Note that
you must restart any daemons using SSL. (E.g., ssh or ssl-enabled
apache.) If you are uncertain which programs are using SSL you may
choose to reboot to ensure that all running daemons are using the new
libraries."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-136"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected openssl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/07/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/07/30");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"libssl-dev", reference:"0.9.6c-0.potato.4")) flag++;
if (deb_check(release:"2.2", prefix:"libssl0.9.6", reference:"0.9.6c-0.potato.4")) flag++;
if (deb_check(release:"2.2", prefix:"libssl09", reference:"0.9.4-6.potato.2")) flag++;
if (deb_check(release:"2.2", prefix:"openssl", reference:"0.9.6c-0.potato.4")) flag++;
if (deb_check(release:"2.2", prefix:"ssleay", reference:"0.9.6c-0.potato.3")) flag++;
if (deb_check(release:"3.0", prefix:"libssl-dev", reference:"0.9.6c-2.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"libssl0.9.6", reference:"0.9.6c-2.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"libssl09", reference:"0.9.4-6.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"libssl095a", reference:"0.9.5a-6.woody.1")) flag++;
if (deb_check(release:"3.0", prefix:"openssl", reference:"0.9.6c-2.woody.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
