#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3395. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(86795);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/04/28 18:33:24 $");

  script_cve_id("CVE-2015-2695", "CVE-2015-2696", "CVE-2015-2697");
  script_osvdb_id(129480);
  script_xref(name:"DSA", value:"3395");

  script_name(english:"Debian DSA-3395-1 : krb5 - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities were discovered in krb5, the MIT
implementation of Kerberos. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2015-2695
    It was discovered that applications which call
    gss_inquire_context() on a partially-established SPNEGO
    context can cause the GSS-API library to read from a
    pointer using the wrong type, leading to a process
    crash.

  - CVE-2015-2696
    It was discovered that applications which call
    gss_inquire_context() on a partially-established IAKERB
    context can cause the GSS-API library to read from a
    pointer using the wrong type, leading to a process
    crash.

  - CVE-2015-2697
    It was discovered that the build_principal_va() function
    incorrectly handles input strings. An authenticated
    attacker can take advantage of this flaw to cause a KDC
    to crash using a TGS request with a large realm field
    beginning with a null byte."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=803083"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=803084"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=803088"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2696"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-2697"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3395"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 1.10.1+dfsg-5+deb7u4.

For the stable distribution (jessie), these problems have been fixed
in version 1.12.1+dfsg-19+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/11/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/11/09");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"krb5-admin-server", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-doc", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-gss-samples", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-kdc", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-kdc-ldap", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-locales", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-multidev", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-pkinit", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-user", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgssapi-krb5-2", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libgssrpc4", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libk5crypto3", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkadm5clnt-mit8", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkadm5srv-mit8", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkdb5-6", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-3", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-dbg", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-dev", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5support0", reference:"1.10.1+dfsg-5+deb7u4")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-admin-server", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-doc", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-gss-samples", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-kdc", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-kdc-ldap", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-locales", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-multidev", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-otp", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-pkinit", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"krb5-user", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgssapi-krb5-2", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libgssrpc4", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libk5crypto3", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkadm5clnt-mit9", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkadm5srv-mit9", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkdb5-7", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrad-dev", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrad0", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrb5-3", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrb5-dbg", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrb5-dev", reference:"1.12.1+dfsg-19+deb8u1")) flag++;
if (deb_check(release:"8.0", prefix:"libkrb5support0", reference:"1.12.1+dfsg-19+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
