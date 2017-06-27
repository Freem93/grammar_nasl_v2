#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1495. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(31055);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-5198", "CVE-2007-5623");
  script_osvdb_id(40391, 41639);
  script_xref(name:"DSA", value:"1495");

  script_name(english:"Debian DSA-1495-1 : nagios-plugins - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local/remote vulnerabilities have been discovered in two of
the plugins for the Nagios network monitoring and management system.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2007-5198
    A buffer overflow has been discovered in the parser for
    HTTP Location headers (present in the check_http
    module).

  - CVE-2007-5623
    A buffer overflow has been discovered in the check_snmp
    module."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1495"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nagios-plugins package.

For the old stable distribution (sarge), these problems have been
fixed in version 1.4-6sarge1.

For the stable distribution (etch), these problems have been fixed in
version 1.4.5-1etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nagios-plugins");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/02/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"nagios-plugins", reference:"1.4-6sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"nagios-plugins", reference:"1.4.5-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"nagios-plugins-basic", reference:"1.4.5-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"nagios-plugins-standard", reference:"1.4.5-1etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
