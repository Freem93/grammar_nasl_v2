#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-288. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15125);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2013/05/18 00:07:14 $");

  script_cve_id("CVE-2003-0131", "CVE-2003-0147");
  script_bugtraq_id(7101, 7148);
  script_osvdb_id(3946);
  script_xref(name:"CERT", value:"888801");
  script_xref(name:"DSA", value:"288");

  script_name(english:"Debian DSA-288-1 : openssl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Researchers discovered two flaws in OpenSSL, a Secure Socket Layer
(SSL) library and related cryptographic tools. Applications that are
linked against this library are generally vulnerable to attacks that
could leak the server's private key or make the encrypted session
decryptable otherwise. The Common Vulnerabilities and Exposures (CVE)
project identified the following vulnerabilities :

 CAN-2003-0147 OpenSSL does not use RSA blinding by default, which
 allows local and remote attackers to obtain the server's private key.
 CAN-2003-0131 The SSL allows remote attackers to perform an
 unauthorized RSA private key operation that causes OpenSSL to leak
 information regarding the relationship between ciphertext and the
 associated plaintext."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-288"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages immediately and restart the applications
that use OpenSSL.

For the stable distribution (woody) these problems have been fixed in
version 0.9.6c-2.woody.3.

For the old stable distribution (potato) these problems have been
fixed in version 0.9.6c-0.potato.6.

Unfortunately, RSA blinding is not thread-safe and will cause failures
for programs that use threads and OpenSSL such as stunnel. However,
since the proposed fix would change the binary interface (ABI),
programs that are dynamically linked against OpenSSL won't run
anymore. This is a dilemma we can't solve.

You will have to decide whether you want the security update which is
not thread-safe and recompile all applications that apparently fail
after the upgrade, or fetch the additional source packages at the end
of this advisory, recompile it and use a thread-safe OpenSSL library
again, but also recompile all applications that make use of it (such
as apache-ssl, mod_ssl, ssh etc.).

However, since only very few packages use threads and link against the
OpenSSL library most users will be able to use packages from this
update without any problems."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:2.2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/04/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2003/03/19");
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
if (deb_check(release:"2.2", prefix:"libssl-dev", reference:"0.9.6c-0.potato.6")) flag++;
if (deb_check(release:"2.2", prefix:"libssl0.9.6", reference:"0.9.6c-0.potato.6")) flag++;
if (deb_check(release:"2.2", prefix:"openssl", reference:"0.9.6c-0.potato.6")) flag++;
if (deb_check(release:"2.2", prefix:"ssleay", reference:"0.9.6c-0.potato.6")) flag++;
if (deb_check(release:"3.0", prefix:"libssl-dev", reference:"0.9.6c-2.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"libssl0.9.6", reference:"0.9.6c-2.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"openssl", reference:"0.9.6c-2.woody.3")) flag++;
if (deb_check(release:"3.0", prefix:"ssleay", reference:"0.9.6c-2.woody.3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
