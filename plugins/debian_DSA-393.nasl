#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-393. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15230);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544");
  script_bugtraq_id(8732);
  script_osvdb_id(3686, 3949);
  script_xref(name:"DSA", value:"393");

  script_name(english:"Debian DSA-393-1 : openssl - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Dr. Stephen Henson (), using a test suite provided by NISCC (),
discovered a number of errors in the OpenSSL ASN1 code. Combined with
an error that causes the OpenSSL code to parse client certificates
even when it should not, these errors can cause a denial of service
(DoS) condition on a system using the OpenSSL code, depending on how
that code is used. For example, even though apache-ssl and ssh link to
OpenSSL libraries, they should not be affected by this vulnerability.
However, other SSL-enabled applications may be vulnerable and an
OpenSSL upgrade is recommended."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-393"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) these problems have been
fixed in version 0.9.6c-2.woody.4.

We recommend that you update your openssl package. Note that you will
need to restart services which use the libssl library for this update
to take effect."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/07/14");
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
if (deb_check(release:"3.0", prefix:"libssl-dev", reference:"0.9.6c-2.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"libssl0.9.6", reference:"0.9.6c-2.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"openssl", reference:"0.9.6c-2.woody.4")) flag++;
if (deb_check(release:"3.0", prefix:"ssleay", reference:"0.9.6c-2.woody.4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
