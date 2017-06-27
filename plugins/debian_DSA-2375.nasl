#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2375. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57515);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/05/22 14:14:42 $");

  script_cve_id("CVE-2011-4862");
  script_osvdb_id(78020);
  script_xref(name:"DSA", value:"2375");

  script_name(english:"Debian DSA-2375-1 : krb5, krb5-appl - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the encryption support for BSD telnetd contains
a pre-authentication buffer overflow, which may enable remote
attackers who can connect to the Telnet port to execute arbitrary code
with root privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/krb5-appl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2375"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 and krb5-appl packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.6.dfsg.4~beta1-5lenny7 of krb5.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.0.1-1.2 of krb5-appl."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-760");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux BSD-derived Telnet Service Encryption Key ID Buffer Overflow');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5-appl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"krb5", reference:"1.6.dfsg.4~beta1-5lenny7")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-clients", reference:"1:1.0.1-1.2")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-ftpd", reference:"1:1.0.1-1.2")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-rsh-server", reference:"1:1.0.1-1.2")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-telnetd", reference:"1:1.0.1-1.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
