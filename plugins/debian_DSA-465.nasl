#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-465. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15302);
  script_version("$Revision: 1.23 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2004-0079", "CVE-2004-0081");
  script_bugtraq_id(9899);
  script_osvdb_id(4317, 4318);
  script_xref(name:"CERT", value:"288574");
  script_xref(name:"CERT", value:"465542");
  script_xref(name:"DSA", value:"465");

  script_name(english:"Debian DSA-465-1 : openssl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities were discovered in openssl, an implementation of
the SSL protocol, using the Codenomicon TLS Test Tool. More
information can be found in the following NISCC Vulnerability Advisory
and this OpenSSL advisory. The Common Vulnerabilities and Exposures
project identified the following vulnerabilities :

  - CAN-2004-0079
    NULL pointer assignment in the do_change_cipher_spec()
    function. A remote attacker could perform a carefully
    crafted SSL/TLS handshake against a server that used the
    OpenSSL library in such a way as to cause OpenSSL to
    crash. Depending on the application this could lead to a
    denial of service.

  - CAN-2004-0081

    A bug in older versions of OpenSSL 0.9.6 that can lead
    to a Denial of Service attack (infinite loop)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.uniras.gov.uk/vuls/2004/224012/index.htm"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.openssl.org/news/secadv/20040317.txt"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-465"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) these problems have been fixed in
openssl version 0.9.6c-2.woody.6, openssl094 version 0.9.4-6.woody.4
and openssl095 version 0.9.5a-6.woody.5.

We recommend that you update your openssl package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl094");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl095");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/03/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/03/17");
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
if (deb_check(release:"3.0", prefix:"libssl-dev", reference:"0.9.6c-2.woody.6")) flag++;
if (deb_check(release:"3.0", prefix:"libssl0.9.6", reference:"0.9.6c-2.woody.6")) flag++;
if (deb_check(release:"3.0", prefix:"libssl09", reference:"0.9.4-6.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"libssl095a", reference:"0.9.5a-6.woody.5")) flag++;
if (deb_check(release:"3.0", prefix:"openssl", reference:"0.9.6c-2.woody.6")) flag++;
if (deb_check(release:"3.0", prefix:"ssleay", reference:"0.9.6c-2.woody.6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
