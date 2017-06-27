#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2123. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(50452);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2014/09/17 11:05:42 $");

  script_cve_id("CVE-2010-3170", "CVE-2010-3173");
  script_bugtraq_id(42817);
  script_xref(name:"DSA", value:"2123");

  script_name(english:"Debian DSA-2123-1 : nss - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Mozilla's Network
Security Services (NSS) library. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2010-3170
    NSS recognizes a wildcard IP address in the subject's
    Common Name field of an X.509 certificate, which might
    allow man-in-the-middle attackers to spoof arbitrary SSL
    servers via a crafted certificate issued by a legitimate
    Certification Authority.

  - CVE-2010-3173
    NSS does not properly set the minimum key length for
    Diffie-Hellman Ephemeral (DHE) mode, which makes it
    easier for remote attackers to defeat cryptographic
    protection mechanisms via a brute-force attack."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3173"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2123"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the NSS packages.

For the stable distribution (lenny), these problems have been fixed in
version 3.12.3.1-0lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/11/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libnss3-1d", reference:"3.12.3.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libnss3-1d-dbg", reference:"3.12.3.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libnss3-dev", reference:"3.12.3.1-0lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"libnss3-tools", reference:"3.12.3.1-0lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
