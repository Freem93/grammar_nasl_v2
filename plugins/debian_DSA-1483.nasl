#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1483. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(30223);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2013/05/17 23:45:45 $");

  script_cve_id("CVE-2007-5846");
  script_osvdb_id(38904);
  script_xref(name:"DSA", value:"1483");

  script_name(english:"Debian DSA-1483-1 : net-snmp - design error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The SNMP agent (snmp_agent.c) in net-snmp before 5.4.1 allows remote
attackers to cause a denial of service (CPU and memory consumption)
via a GETBULK request with a large max-repeaters value."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1483"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the net-snmp package.

For the stable distribution (etch), this problem has been fixed in
version 5.2.3-7etch2.

For the unstable and testing distributions (sid and lenny,
respectively), this problem has been fixed in version 5.4.1~dfsg-2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:net-snmp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/05/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"libsnmp-base", reference:"5.2.3-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libsnmp-perl", reference:"5.2.3-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libsnmp9", reference:"5.2.3-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"libsnmp9-dev", reference:"5.2.3-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"snmp", reference:"5.2.3-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"snmpd", reference:"5.2.3-7etch2")) flag++;
if (deb_check(release:"4.0", prefix:"tkmib", reference:"5.2.3-7etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
