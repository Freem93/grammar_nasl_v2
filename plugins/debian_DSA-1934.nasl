#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1934. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44799);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-3094", "CVE-2009-3095", "CVE-2009-3555");
  script_bugtraq_id(36254, 36260, 36935);
  script_osvdb_id(61234, 61718);
  script_xref(name:"DSA", value:"1934");

  script_name(english:"Debian DSA-1934-1 : apache2 - multiple issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A design flaw has been found in the TLS and SSL protocol that allows
an attacker to inject arbitrary content at the beginning of a TLS/SSL
connection. The attack is related to the way how TLS and SSL handle
session renegotiations. CVE-2009-3555 has been assigned to this
vulnerability.

As a partial mitigation against this attack, this apache2 update
disables client-initiated renegotiations. This should fix the
vulnerability for the majority of Apache configurations in use.

NOTE: This is not a complete fix for the problem. The attack is still
possible in configurations where the server initiates the
renegotiation. This is the case for the following configurations (the
information in the changelog of the updated packages is slightly
inaccurate) :

  - The 'SSLVerifyClient' directive is used in a Directory
    or Location context.
  - The 'SSLCipherSuite' directive is used in a Directory or
    Location context.

As a workaround, you may rearrange your configuration in a way that
SSLVerifyClient and SSLCipherSuite are only used on the server or
virtual host level.


A complete fix for the problem will require a protocol change. Further
information will be included in a separate announcement about this
issue.

In addition, this update fixes the following issues in Apache's
mod_proxy_ftp :

  - CVE-2009-3094
    Insufficient input validation in the mod_proxy_ftp
    module allowed remote FTP servers to cause a denial of
    service (NULL pointer dereference and child process
    crash) via a malformed reply to an EPSV command.

  - CVE-2009-3095
    Insufficient input validation in the mod_proxy_ftp
    module allowed remote authenticated attackers to bypass
    intended access restrictions and send arbitrary FTP
    commands to an FTP server."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3555"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3094"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3095"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1934"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 and apache2-mpm-itk packages.

For the oldstable distribution (etch), these problems have been fixed
in version 2.2.3-4+etch11.

For the stable distribution (lenny), these problems have been fixed in
version 2.2.9-10+lenny6. This version also includes some non-security
bug fixes that were scheduled for inclusion in the next stable point
release (Debian 5.0.4).

This advisory also provides updated apache2-mpm-itk packages which
have been recompiled against the new apache2 packages.

Updated apache2-mpm-itk packages for the armel architecture are not
included yet. They will be released as soon as they become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:ND/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(119, 264, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/11/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"apache2", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-doc", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-event", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-itk", reference:"2.2.3-01-2+etch4+b1")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-perchild", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-prefork", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-worker", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-prefork-dev", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-src", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-threaded-dev", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-utils", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"4.0", prefix:"apache2.2-common", reference:"2.2.3-4+etch11")) flag++;
if (deb_check(release:"5.0", prefix:"apache2", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-dbg", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-doc", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-event", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-itk", reference:"2.2.6-02-1+lenny2+b2")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-prefork", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-worker", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-prefork-dev", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-src", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec-custom", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-threaded-dev", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-utils", reference:"2.2.9-10+lenny6")) flag++;
if (deb_check(release:"5.0", prefix:"apache2.2-common", reference:"2.2.9-10+lenny6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
