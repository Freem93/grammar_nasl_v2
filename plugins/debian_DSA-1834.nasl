#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1834. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44699);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-1890", "CVE-2009-1891");
  script_bugtraq_id(35565, 35623);
  script_xref(name:"DSA", value:"1834");

  script_name(english:"Debian DSA-1834-1 : apache2 - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"- CVE-2009-1890
    A denial of service flaw was found in the Apache
    mod_proxy module when it was used as a reverse proxy. A
    remote attacker could use this flaw to force a proxy
    process to consume large amounts of CPU time. This issue
    did not affect Debian 4.0 'etch'.

  - CVE-2009-1891
    A denial of service flaw was found in the Apache
    mod_deflate module. This module continued to compress
    large files until compression was complete, even if the
    network connection that requested the content was closed
    before compression completed. This would cause
    mod_deflate to consume large amounts of CPU if
    mod_deflate was enabled for a large file. A similar flaw
    related to HEAD requests for compressed content was also
    fixed.

The oldstable distribution (etch), these problems have been fixed in
version 2.2.3-4+etch9."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1890"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1891"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1834"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (lenny), these problems have been fixed in
version 2.2.9-10+lenny4.

This advisory also provides updated apache2-mpm-itk packages which
have been recompiled against the new apache2 packages.

Updated packages for the s390 and mipsel architectures are not
included yet. They will be released as soon as they become available."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/07/15");
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
if (deb_check(release:"4.0", prefix:"apache2", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-doc", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-event", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-itk", reference:"2.2.3-01-2+etch3")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-perchild", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-prefork", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-mpm-worker", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-prefork-dev", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-src", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-threaded-dev", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2-utils", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"4.0", prefix:"apache2.2-common", reference:"2.2.3-4+etch9")) flag++;
if (deb_check(release:"5.0", prefix:"apache2", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-dbg", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-doc", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-event", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-itk", reference:"2.2.6-02-1+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-prefork", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-mpm-worker", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-prefork-dev", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-src", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-suexec-custom", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-threaded-dev", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2-utils", reference:"2.2.9-10+lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"apache2.2-common", reference:"2.2.9-10+lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
