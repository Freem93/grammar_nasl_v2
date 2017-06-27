#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1874. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44739);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-2404", "CVE-2009-2408", "CVE-2009-2409");
  script_bugtraq_id(35888, 35891);
  script_osvdb_id(56723, 56724, 56752);
  script_xref(name:"DSA", value:"1874");

  script_name(english:"Debian DSA-1874-1 : nss - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the Network Security
Service libraries. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-2404
    Moxie Marlinspike discovered that a buffer overflow in
    the regular expression parser could lead to the
    execution of arbitrary code.

  - CVE-2009-2408
    Dan Kaminsky discovered that NULL characters in
    certificate names could lead to man-in-the-middle
    attacks by tricking the user into accepting a rogue
    certificate.

  - CVE-2009-2409
    Certificates with MD2 hash signatures are no longer
    accepted since they're no longer considered
    cryptograhically secure."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2404"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1874"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

The old stable distribution (etch) doesn't contain nss.

For the stable distribution (lenny), these problems have been fixed in
version 3.12.3.1-0lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"libnss3-1d", reference:"3.12.3.1-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnss3-1d-dbg", reference:"3.12.3.1-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnss3-dev", reference:"3.12.3.1-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libnss3-tools", reference:"3.12.3.1-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
