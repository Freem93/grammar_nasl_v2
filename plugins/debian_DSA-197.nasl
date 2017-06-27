#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-197. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15034);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2013/05/17 23:54:23 $");

  script_cve_id("CVE-2002-1311");
  script_osvdb_id(14521);
  script_xref(name:"DSA", value:"197");

  script_name(english:"Debian DSA-197-1 : courier - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A problem in the Courier sqwebmail package, a CGI program to grant
authenticated access to local mailboxes, has been discovered. The
program did not drop permissions fast enough upon startup under
certain circumstances so a local shell user can execute the sqwebmail
binary and manage to read an arbitrary file on the local filesystem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2002/dsa-197"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sqwebmail package immediately.

This problem has been fixed in version 0.37.3-2.3 for the current
stable distribution (woody) and in version 0.40.0-1 for the unstable
distribution (sid). The old stable distribution (potato) does not
contain Courier sqwebmail packages. courier-ssl packages are also not
affected since they don't expose an sqwebmail package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:courier");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2002/11/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2002/11/15");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"courier-authdaemon", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-authmysql", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-base", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-debug", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-doc", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-imap", reference:"1.4.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-imap-ssl", reference:"1.4.3-3.1")) flag++;
if (deb_check(release:"3.0", prefix:"courier-ldap", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-maildrop", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mlm", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-mta", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pcp", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-pop", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"courier-webadmin", reference:"0.37.3-2.3")) flag++;
if (deb_check(release:"3.0", prefix:"sqwebmail", reference:"0.37.3-2.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
