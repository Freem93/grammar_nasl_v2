#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-394. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15231);
  script_version("$Revision: 1.25 $");
  script_cvs_date("$Date: 2016/05/05 16:01:12 $");

  script_cve_id("CVE-2003-0543", "CVE-2003-0544", "CVE-2003-0545");
  script_bugtraq_id(8732);
  script_osvdb_id(3684, 3686, 3949);
  script_xref(name:"DSA", value:"394");

  script_name(english:"Debian DSA-394-1 : openssl095 - ASN.1 parsing vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Steve Henson of the OpenSSL core team identified and prepared fixes
for a number of vulnerabilities in the OpenSSL ASN1 code that were
discovered after running a test suite by British National
Infrastructure Security Coordination Centre (NISCC).

A bug in OpenSSLs SSL/TLS protocol was also identified which causes
OpenSSL to parse a client certificate from an SSL/TLS client when it
should reject it as a protocol error.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CAN-2003-0543 :
    Integer overflow in OpenSSL that allows remote attackers
    to cause a denial of service (crash) via an SSL client
    certificate with certain ASN.1 tag values.

  - CAN-2003-0544 :

    OpenSSL does not properly track the number of characters
    in certain ASN.1 inputs, which allows remote attackers
    to cause a denial of service (crash) via an SSL client
    certificate that causes OpenSSL to read past the end of
    a buffer when the long form is used.

  - CAN-2003-0545 :

    Double-free vulnerability allows remote attackers to
    cause a denial of service (crash) and possibly execute
    arbitrary code via an SSL client certificate with a
    certain invalid ASN.1 encoding. This bug was only
    present in OpenSSL 0.9.7 and is listed here only for
    reference."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-394"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libssl095a packages and restart services using this
library. Debian doesn't ship any packages that are linked against this
library.

For the stable distribution (woody) this problem has been fixed in
openssl095 version 0.9.5a-6.woody.3.

This package is not present in the unstable (sid) or testing (sarge)
distribution.

The following commandline (courtesy of Ray Dassen) produces a list of
names of running processes that have libssl095 mapped into their
memory space :

    find /proc -name maps -exec egrep -l 'libssl095' {} /dev/null \; |
    sed -e 's/[^0-9]//g' | xargs --no-run-if-empty ps --no-headers -p
    | sed -e 's/^\+//' -e 's/ \+/ /g' | cut -d ' ' -f 5 | sort | uniq

You should restart the associated services."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl095");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/11");
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
if (deb_check(release:"3.0", prefix:"libssl095a", reference:"0.9.5a-6.woody.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
