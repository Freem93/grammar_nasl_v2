#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1189. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22731);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2006-4924", "CVE-2006-5051");
  script_osvdb_id(29152, 29264);
  script_xref(name:"DSA", value:"1189");

  script_name(english:"Debian DSA-1189-1 : openssh-krb5 - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in OpenSSH, a free
implementation of the Secure Shell protocol, which may lead to denial
of service and potentially the execution of arbitrary code. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2006-4924
    Tavis Ormandy of the Google Security Team discovered a
    denial of service vulnerability in the mitigation code
    against complexity attacks, which might lead to
    increased CPU consumption until a timeout is triggered.
    This is only exploitable if support for SSH protocol
    version 1 is enabled.

  - CVE-2006-5051
    Mark Dowd discovered that insecure signal handler usage
    could potentially lead to execution of arbitrary code
    through a double free. The Debian Security Team doesn't
    believe the general openssh package without Kerberos
    support to be exploitable by this issue. However, due to
    the complexity of the underlying code we will issue an
    update to rule out all eventualities."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4924"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-5051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1189"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssh-krb5 packages.

For the stable distribution (sarge) these problems have been fixed in
version 3.8.1p1-7sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssh-krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ssh-krb5", reference:"3.8.1p1-7sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
