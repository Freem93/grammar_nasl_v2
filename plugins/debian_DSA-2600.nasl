#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2600. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63385);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-5519");
  script_bugtraq_id(56494);
  script_xref(name:"DSA", value:"2600");

  script_name(english:"Debian DSA-2600-1 : cups - privilege escalation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jann Horn discovered that users of the CUPS printing system who are
part of the lpadmin group could modify several configuration
parameters with security impact. Specifically, this allows an attacker
to read or write arbitrary files as root which can be used to elevate
privileges.

This update splits the configuration file /etc/cups/cupsd.conf into
two files: cupsd.conf and cups-files.conf. While the first stays
configurable via the web interface, the latter can only be configured
by the root user. Please see the updated documentation that comes with
the new package for more information on these files."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=692791"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/cups"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2600"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cups packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.4.4-7+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cups");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"cups", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cups-bsd", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cups-client", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cups-common", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cups-dbg", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cups-ppdc", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"cupsddk", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcups2-dev", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupscgi1-dev", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsdriver1-dev", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsimage2-dev", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsmime1-dev", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1", reference:"1.4.4-7+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcupsppdc1-dev", reference:"1.4.4-7+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
