#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2621. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64623);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2013-0166", "CVE-2013-0169");
  script_bugtraq_id(57755, 57778);
  script_osvdb_id(89848, 89865);
  script_xref(name:"DSA", value:"2621");

  script_name(english:"Debian DSA-2621-1 : openssl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been found in OpenSSL. The Common
Vulnerabilities and Exposures project identifies the following issues
:

  - CVE-2013-0166
    OpenSSL does not properly perform signature verification
    for OCSP responses, which allows remote attackers to
    cause a denial of service via an invalid key.

  - CVE-2013-0169
    A timing side channel attack has been found in CBC
    padding allowing an attacker to recover pieces of
    plaintext via statistical analysis of crafted packages,
    known as the 'Lucky Thirteen' issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=699889"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0166"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-0169"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2621"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the stable distribution (squeeze), these problems have been fixed
in version 0.9.8o-4squeeze14."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libcrypto0.9.8-udeb", reference:"0.9.8o-4squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libssl-dev", reference:"0.9.8o-4squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8", reference:"0.9.8o-4squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8o-4squeeze14")) flag++;
if (deb_check(release:"6.0", prefix:"openssl", reference:"0.9.8o-4squeeze14")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
