#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1257. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24296);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-0452", "CVE-2007-0454");
  script_osvdb_id(33100, 33101);
  script_xref(name:"DSA", value:"1257");

  script_name(english:"Debian DSA-1257-1 : samba - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in samba, a free
implementation of the SMB/CIFS protocol, which may lead to the
execution of arbitrary code or denial of service. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-0452
    It was discovered that incorrect handling of deferred
    file open calls may lead to an infinite loop, which
    results in denial of service.

  - CVE-2007-0454
    'zybadawg333' discovered that the AFS ACL mapping VFS
    plugin performs insecure format string handling, which
    may lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1257"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the samba package.

For the stable distribution (sarge) these problems have been fixed in
version 3.0.14a-3sarge4.

For the upcoming stable distribution (etch) these problems have been
fixed in version 3.0.23d-5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:samba");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/02/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/02/09");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/02/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libpam-smbpass", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"libsmbclient-dev", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"python2.3-samba", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"samba", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"samba-common", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"samba-dbg", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"samba-doc", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"smbclient", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"smbfs", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"swat", reference:"3.0.14a-3sarge4")) flag++;
if (deb_check(release:"3.1", prefix:"winbind", reference:"3.0.14a-3sarge4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
