#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2007. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44988);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2013/05/17 23:54:24 $");

  script_cve_id("CVE-2010-0393");
  script_bugtraq_id(38524);
  script_xref(name:"DSA", value:"2007");

  script_name(english:"Debian DSA-2007-1 : cups - format string vulnerability");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ronald Volgers discovered that the lppasswd component of the cups
suite, the Common UNIX Printing System, is vulnerable to format string
attacks due to insecure use of the LOCALEDIR environment variable. An
attacker can abuse this behaviour to execute arbitrary code via
crafted localization files and triggering calls to _cupsLangprintf().
This works as the lppasswd binary happens to be installed with setuid
0 permissions."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2007"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the stable distribution (lenny), this problem has been fixed in
version 1.3.8-1+lenny8."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_cwe_id(264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"cups", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cups-bsd", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cups-client", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cups-common", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cups-dbg", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-bsd", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-client", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-common", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"cupsys-dbg", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libcups2", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libcups2-dev", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsimage2", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsimage2-dev", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsys2", reference:"1.3.8-1+lenny8")) flag++;
if (deb_check(release:"5.0", prefix:"libcupsys2-dev", reference:"1.3.8-1+lenny8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
