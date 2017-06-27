#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3000. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77101);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-4341", "CVE-2014-4342", "CVE-2014-4343", "CVE-2014-4344", "CVE-2014-4345");
  script_bugtraq_id(68908, 68909, 69159, 69160);
  script_osvdb_id(108748, 108751, 109389, 109390, 109908);
  script_xref(name:"DSA", value:"3000");

  script_name(english:"Debian DSA-3000-1 : krb5 - security update");
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

  - CVE-2014-4341
    An unauthenticated remote attacker with the ability to
    inject packets into a legitimately established GSSAPI
    application session can cause a program crash due to
    invalid memory references when attempting to read beyond
    the end of a buffer.

  - CVE-2014-4342
    An unauthenticated remote attacker with the ability to
    inject packets into a legitimately established GSSAPI
    application session can cause a program crash due to
    invalid memory references when reading beyond the end of
    a buffer or by causing a NULL pointer dereference.

  - CVE-2014-4343
    An unauthenticated remote attacker with the ability to
    spoof packets appearing to be from a GSSAPI acceptor can
    cause a double-free condition in GSSAPI initiators
    (clients) which are using the SPNEGO mechanism, by
    returning a different underlying mechanism than was
    proposed by the initiator. A remote attacker could
    exploit this flaw to cause an application crash or
    potentially execute arbitrary code.

  - CVE-2014-4344
    An unauthenticated or partially authenticated remote
    attacker can cause a NULL dereference and application
    crash during a SPNEGO negotiation by sending an empty
    token as the second or later context token from
    initiator to acceptor.

  - CVE-2014-4345
    When kadmind is configured to use LDAP for the KDC
    database, an authenticated remote attacker can cause it
    to perform an out-of-bounds write (buffer overflow)."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=753624"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=753625"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=755520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=755521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=757416"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4341"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4342"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4343"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4344"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2014-4345"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/krb5"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3000"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the krb5 packages.

For the stable distribution (wheezy), these problems have been fixed
in version 1.10.1+dfsg-5+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:krb5");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/08/09");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/08/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"krb5-admin-server", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-doc", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-gss-samples", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-kdc", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-kdc-ldap", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-locales", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-multidev", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-pkinit", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"krb5-user", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgssapi-krb5-2", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libgssrpc4", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libk5crypto3", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkadm5clnt-mit8", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkadm5srv-mit8", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkdb5-6", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-3", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-dbg", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5-dev", reference:"1.10.1+dfsg-5+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libkrb5support0", reference:"1.10.1+dfsg-5+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
