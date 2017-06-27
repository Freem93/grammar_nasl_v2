#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1222. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(23757);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2006-5815", "CVE-2006-6170", "CVE-2006-6171");
  script_osvdb_id(30267, 30660, 30719);
  script_xref(name:"DSA", value:"1222");

  script_name(english:"Debian DSA-1222-2 : proftpd - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Due to technical problems yesterday's proftpd update lacked a build
for the amd64 architecture, which is now available. For reference
please find below the original advisory text :

  Several remote vulnerabilities have been discovered in the proftpd
  FTP daemon, which may lead to the execution of arbitrary code or
  denial of service. The Common Vulnerabilities and Exposures project
  identifies the following problems :

    - CVE-2006-5815
      It was discovered that a buffer overflow in the
      sreplace() function may lead to denial of service and
      possibly the execution of arbitrary code.

    - CVE-2006-6170
      It was discovered that a buffer overflow in the
      mod_tls addon module may lead to the execution of
      arbitrary code.

    - CVE-2006-6171
      It was discovered that insufficient validation of FTP
      command buffer size limits may lead to denial of
      service. Due to unclear information this issue was
      already fixed in DSA-1218 as CVE-2006-5815."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=399070"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6170"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-6171"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5815"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1222"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd package.

For the stable distribution (sarge) these problems have been fixed in
version 1.2.10-15sarge3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'ProFTPD 1.2 - 1.3.0 sreplace Buffer Overflow (Linux)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2006/12/04");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/10/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"proftpd", reference:"1.2.10-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-common", reference:"1.2.10-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-doc", reference:"1.2.10-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-ldap", reference:"1.2.10-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-mysql", reference:"1.2.10-15sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-pgsql", reference:"1.2.10-15sarge3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
