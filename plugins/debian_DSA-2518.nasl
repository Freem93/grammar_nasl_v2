#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2518. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61374);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-1014", "CVE-2012-1015");
  script_osvdb_id(84423, 84424);
  script_xref(name:"DSA", value:"2518");

  script_name(english:"Debian DSA-2518-1 : krb5 - denial of service and remote code execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Emmanuel Bouillon from NCI Agency discovered multiple vulnerabilities
in MIT Kerberos, a daemon implementing the network authentication
protocol.

  - CVE-2012-1014
    By sending specially crafted AS-REQ (Authentication
    Service Request) to a KDC (Key Distribution Center), an
    attacker could make it free an uninitialized pointer,
    corrupting the heap. This can lead to process crash or
    even arbitrary code execution.

  This CVE only affects testing (wheezy) and unstable (sid)
  distributions.

  - CVE-2012-1015
    By sending specially crafted AS-REQ to a KDC, an
    attacker could make it dereference an uninitialized
    pointer, leading to process crash or even arbitrary code
    execution

In both cases, arbitrary code execution is believed to be difficult to
achieve, but might not be impossible."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=683429"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1014"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1015"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2518"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.8.3+dfsg-4squeeze6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"krb5-admin-server", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-doc", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-kdc-ldap", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-multidev", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-pkinit", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"krb5-user", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb5-dev", reference:"1.8.3+dfsg-4squeeze6")) flag++;
if (deb_check(release:"6.0", prefix:"libkrb53", reference:"1.8.3+dfsg-4squeeze6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
