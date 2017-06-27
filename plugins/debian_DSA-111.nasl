#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-111. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(14948);
  script_version("$Revision: 1.21 $");
  script_cvs_date("$Date: 2013/05/17 23:36:52 $");

  script_xref(name:"CERT", value:"107186");
  script_xref(name:"CERT", value:"854306");
  script_xref(name:"DSA", value:"111");

  script_name(english:"Debian DSA-111-1 : ucd-snmp - remote exploit");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The Secure Programming Group of the Oulu University did a study on
SNMP implementations and uncovered multiple problems which can cause
problems ranging from Denial of Service attacks to remote exploits.

New UCD-SNMP packages have been prepared to fix these problems as well
as a few others. The complete list of fixed problems is :

  - When running external programs snmpd used temporary
    files insecurely
  - snmpd did not properly reset supplementary groups after
    changing its uid and gid

  - Modified most code to use buffers instead of
    fixed-length strings to prevent buffer overflows

  - The ASN.1 parser did not check for negative lengths

  - The IFINDEX response handling in snmpnetstat did not do
    a sanity check on its input

(thanks to Caldera for most of the work on those patches)


The new version is 4.1.1-2.1 and we recommend you upgrade your snmp
packages immediately."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-111"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Upgrade the affected ucd-snmp package."
  );
  script_set_attribute(attribute:"risk_factor", value:"High");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ucd-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/02/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"2.2", prefix:"libsnmp4.1", reference:"4.1.1-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"libsnmp4.1-dev", reference:"4.1.1-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"snmp", reference:"4.1.1-2.2")) flag++;
if (deb_check(release:"2.2", prefix:"snmpd", reference:"4.1.1-2.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
