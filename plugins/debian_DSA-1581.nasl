#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1581. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32403);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-1948", "CVE-2008-1949", "CVE-2008-1950");
  script_bugtraq_id(29292);
  script_osvdb_id(45382, 45383, 45384);
  script_xref(name:"DSA", value:"1581");

  script_name(english:"Debian DSA-1581-1 : gnutls13 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in GNUTLS, an
implementation of the SSL/TLS protocol suite.

NOTE: The libgnutls13 package, which provides the GNUTLS library, does
not contain logic to automatically restart potentially affected
services. You must restart affected services manually (mainly Exim,
using '/etc/init.d/exim4 restart') after applying the update, to make
the changes fully effective. Alternatively, you can reboot the system.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2008-1948
    A pre-authentication heap overflow involving oversized
    session resumption data may lead to arbitrary code
    execution.

  - CVE-2008-1949
    Repeated client hellos may result in a
    pre-authentication denial of service condition due to a
    NULL pointer dereference.

  - CVE-2008-1950
    Decoding cipher padding with an invalid record length
    may cause GNUTLS to read memory beyond the end of the
    received record, leading to a pre-authentication denial
    of service condition."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1948"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1949"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1950"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1581"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the GNUTLS packages.

For the stable distribution (etch), these problems have been fixed in
version 1.4.4-3+etch1. (Builds for the arm architecture are currently
not available and will be released later.)"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:gnutls13");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"gnutls-bin", reference:"1.4.4-3+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"gnutls-doc", reference:"1.4.4-3+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls-dev", reference:"1.4.4-3+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls13", reference:"1.4.4-3+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libgnutls13-dbg", reference:"1.4.4-3+etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
