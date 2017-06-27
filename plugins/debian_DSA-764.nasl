#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-764. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19258);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2015/07/10 14:11:55 $");

  script_cve_id("CVE-2005-1524", "CVE-2005-1525", "CVE-2005-1526", "CVE-2005-2148", "CVE-2005-2149");
  script_osvdb_id(17424, 17425, 17426, 17719, 17720, 17721);
  script_xref(name:"DSA", value:"764");

  script_name(english:"Debian DSA-764-1 : cacti - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in cacti, a round-robin
database (RRD) tool that helps create graphs from database
information. The Common Vulnerabilities and Exposures Project
identifies the following problems :

  - CAN-2005-1524
    Maciej Piotr Falkiewicz and an anonymous researcher
    discovered an input validation bug that allows an
    attacker to include arbitrary PHP code from remote sites
    which will allow the execution of arbitrary code on the
    server running cacti.

  - CAN-2005-1525

    Due to missing input validation cacti allows a remote
    attacker to insert arbitrary SQL statements.

  - CAN-2005-1526

    Maciej Piotr Falkiewicz discovered an input validation
    bug that allows an attacker to include arbitrary PHP
    code from remote sites which will allow the execution of
    arbitrary code on the server running cacti.

  - CAN-2005-2148

    Stefan Esser discovered that the update for the above
    mentioned vulnerabilities does not perform proper input
    validation to protect against common attacks.

  - CAN-2005-2149

    Stefan Esser discovered that the update for
    CAN-2005-1525 allows remote attackers to modify session
    information to gain privileges and disable the use of
    addslashes to protect against SQL injection."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=316590"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=315703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-764"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cacti package.

For the old stable distribution (woody) these problems have been fixed
in version 0.6.7-2.5.

For the stable distribution (sarge) these problems have been fixed in
version 0.8.6c-7sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cacti");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/21");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/06/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"cacti", reference:"0.6.7-2.5")) flag++;
if (deb_check(release:"3.1", prefix:"cacti", reference:"0.8.6c-7sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
