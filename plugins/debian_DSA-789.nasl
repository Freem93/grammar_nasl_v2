#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-789. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19532);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/06/14 17:29:37 $");

  script_cve_id("CVE-2005-1751", "CVE-2005-1759", "CVE-2005-1921", "CVE-2005-2498");
  script_osvdb_id(16848, 17289, 17793, 18889);
  script_xref(name:"DSA", value:"789");

  script_name(english:"Debian DSA-789-1 : php4 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been found in PHP4, the
server-side, HTML-embedded scripting language. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CAN-2005-1751
    Eric Romang discovered insecure temporary files in the
    shtool utility shipped with PHP that can exploited by a
    local attacker to overwrite arbitrary files. Only this
    vulnerability affects packages in oldstable.

  - CAN-2005-1921

    GulfTech has discovered that PEAR XML_RPC is vulnerable
    to a remote PHP code execution vulnerability that may
    allow an attacker to compromise a vulnerable server.

  - CAN-2005-2498

    Stefan Esser discovered another vulnerability in the
    XML-RPC libraries that allows injection of arbitrary PHP
    code into eval() statements."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=323366"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-789"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PHP packages.

For the old stable distribution (woody) these problems have been fixed
in version 4.1.2-7.woody5.

For the stable distribution (sarge) these problems have been fixed in
version 4.3.10-16."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'PHP XML-RPC Arbitrary Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/08/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/08/30");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/05/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"caudium-php4", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-cgi", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-curl", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-dev", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-domxml", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-gd", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-imap", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-ldap", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mcal", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mhash", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mysql", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-odbc", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-pear", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-recode", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-snmp", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-sybase", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.0", prefix:"php4-xslt", reference:"4.1.2-7.woody5")) flag++;
if (deb_check(release:"3.1", prefix:"libapache-mod-php4", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"libapache2-mod-php4", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cgi", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-cli", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-common", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-curl", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-dev", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-domxml", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-gd", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-imap", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-ldap", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mcal", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mhash", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-mysql", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-odbc", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-pear", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-recode", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-snmp", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-sybase", reference:"4.3.10-16")) flag++;
if (deb_check(release:"3.1", prefix:"php4-xslt", reference:"4.3.10-16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
