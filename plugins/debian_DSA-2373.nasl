#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2373. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57513);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-4862");
  script_osvdb_id(78020);
  script_xref(name:"DSA", value:"2373");

  script_name(english:"Debian DSA-2373-1 : inetutils - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that the Kerberos support for telnetd contains a
pre-authentication buffer overflow, which may enable remote attackers
who can connect to TELNET to execute arbitrary code with root
privileges."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/inetutils"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2373"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the inetutils packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2:1.5.dfsg.1-9+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 2:1.6-3.1+squeeze1."
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
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:inetutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/25");
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
if (deb_check(release:"5.0", prefix:"inetutils", reference:"2:1.5.dfsg.1-9+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-ftp", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-ftpd", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-inetd", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-ping", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-syslogd", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-talk", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-talkd", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-telnet", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-telnetd", reference:"2:1.6-3.1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"inetutils-tools", reference:"2:1.6-3.1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
