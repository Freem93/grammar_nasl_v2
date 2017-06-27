#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-757. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19219);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2013/05/18 00:15:58 $");

  script_cve_id("CVE-2005-1174", "CVE-2005-1175", "CVE-2005-1689");
  script_osvdb_id(17841, 17843);
  script_xref(name:"CERT", value:"259798");
  script_xref(name:"CERT", value:"623332");
  script_xref(name:"CERT", value:"885830");
  script_xref(name:"DSA", value:"757");

  script_name(english:"Debian DSA-757-1 : krb5 - buffer overflow, double-free memory");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Daniel Wachdorf reported two problems in the MIT krb5 distribution
used for network authentication. First, the KDC program from the
krb5-kdc package can corrupt the heap by trying to free memory which
has already been freed on receipt of a certain TCP connection. This
vulnerability can cause the KDC to crash, leading to a denial of
service. [ CAN-2005-1174] Second, under certain rare circumstances
this type of request can lead to a buffer overflow and remote code
execution. [ CAN-2005-1175] 

Additionally, Magnus Hagander reported another problem in which the
krb5_recvauth function can in certain circumstances free previously
freed memory, potentially leading to the execution of remote code. [
CAN-2005-1689] 

All of these vulnerabilities are believed difficult to exploit, and no
exploits have yet been discovered."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-757"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 package.

For the old stable distribution (woody), these problems have been
fixed in version 1.2.4-5woody10. Note that woody's KDC does not have
TCP support and is not vulnerable to CAN-2005-1174.

For the stable distribution (sarge), these problems have been fixed in
version 1.3.6-2sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/07/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/07/18");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"krb5-admin-server", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-clients", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-doc", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-ftpd", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-kdc", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-rsh-server", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-telnetd", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"krb5-user", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"libkadm55", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb5-dev", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.0", prefix:"libkrb53", reference:"1.2.4-5woody10")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-admin-server", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-clients", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-doc", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-ftpd", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-kdc", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-rsh-server", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-telnetd", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"krb5-user", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkadm55", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb5-dev", reference:"1.3.6-2sarge2")) flag++;
if (deb_check(release:"3.1", prefix:"libkrb53", reference:"1.3.6-2sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
