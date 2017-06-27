#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1730. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35755);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-0542", "CVE-2009-0543");
  script_bugtraq_id(33722);
  script_xref(name:"DSA", value:"1730");

  script_name(english:"Debian DSA-1730-1 : proftpd-dfsg - SQL injection vulnerabilites");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The security update for proftpd-dfsg in DSA-1727-1 caused a regression
with the postgresql backend. This update corrects the flaw. Also it
was discovered that the oldstable distribution (etch) is not affected
by the security issues. For reference the original advisory follows.

Two SQL injection vulnerabilities have been found in proftpd, a
virtual-hosting FTP daemon. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-0542
    Shino discovered that proftpd is prone to a SQL
    injection vulnerability via the use of certain
    characters in the username.

  - CVE-2009-0543
    TJ Saunders discovered that proftpd is prone to a SQL
    injection vulnerability due to insufficient escaping
    mechanisms, when multybite character encodings are used.

The oldstable distribution (etch) is not affected by these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0543"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1730"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (lenny), these problems have been fixed in
version 1.3.1-17lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(89);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd-dfsg");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"proftpd", reference:"1.3.1-17lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-basic", reference:"1.3.1-17lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-doc", reference:"1.3.1-17lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-mod-ldap", reference:"1.3.1-17lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-mod-mysql", reference:"1.3.1-17lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"proftpd-mod-pgsql", reference:"1.3.1-17lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
