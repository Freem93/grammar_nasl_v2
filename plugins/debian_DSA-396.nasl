#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-396. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15233);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/12/06 20:34:49 $");

  script_cve_id("CVE-2002-1562", "CVE-2003-0899");
  script_bugtraq_id(8906, 8924);
  script_xref(name:"DSA", value:"396");

  script_name(english:"Debian DSA-396-1 : thttpd - missing input sanitizing, wrong calculation");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in thttpd, a tiny HTTP
server.

The Common Vulnerabilities and Exposures project identifies the
following vulnerabilities :

  - CAN-2002-1562: Information leak
    Marcus Breiing discovered that if thttpd it is used for
    virtual hosting, and an attacker supplies a specially
    crafted 'Host:' header with a pathname instead of a
    hostname, thttpd will reveal information about the host
    system. Hence, an attacker can browse the entire disk.

  - CAN-2003-0899: Arbitrary code execution
    Joel Soderberg and Christer Oberg discovered a remote
    overflow which allows an attacker to partially overwrite
    the EBP register and hence execute arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-396"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the thttpd package immediately.

For the stable distribution (woody) these problems have been fixed in
version 2.21b-11.2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:thttpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/10/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"thttpd", reference:"2.21b-11.2")) flag++;
if (deb_check(release:"3.0", prefix:"thttpd-util", reference:"2.21b-11.2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
