#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1807. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(39332);
  script_version("$Revision: 1.17 $");
  script_cvs_date("$Date: 2013/05/17 23:49:56 $");

  script_cve_id("CVE-2009-0688");
  script_xref(name:"CERT", value:"238019");
  script_xref(name:"DSA", value:"1807");

  script_name(english:"Debian DSA-1807-1 : cyrus-sasl2, cyrus-sasl2-heimdal - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"James Ralston discovered that the sasl_encode64() function of
cyrus-sasl2, a free library implementing the Simple Authentication and
Security Layer, suffers from a missing null termination in certain
situations. This causes several buffer overflows in situations where
cyrus-sasl2 itself requires the string to be null terminated which can
lead to denial of service or arbitrary code execution.

Important notice (Quoting from US-CERT): While this patch will fix
currently vulnerable code, it can cause non-vulnerable existing code
to break. Here's a function prototype from include/saslutil.h to
clarify my explanation :

/* base64 encode * in -- input data * inlen -- input data length * out
-- output buffer (will be NUL terminated) * outmax -- max size of
output buffer * result: * outlen -- gets actual length of output
buffer (optional) * * Returns SASL_OK on success, SASL_BUFOVER if
result won't fit */ LIBSASL_API int sasl_encode64(const char *in,
unsigned inlen, char *out, unsigned outmax, unsigned *outlen);

Assume a scenario where calling code has been written in such a way
that it calculates the exact size required for base64 encoding in
advance, then allocates a buffer of that exact size, passing a pointer
to the buffer into sasl_encode64() as *out. As long as this code does
not anticipate that the buffer is NUL-terminated (does not call any
string-handling functions like strlen(), for example) the code will
work and it will not be vulnerable.

Once this patch is applied, that same code will break because
sasl_encode64() will begin to return SASL_BUFOVER."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=528749"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1807"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the cyrus-sasl2/cyrus-sasl2-heimdal packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.1.22.dfsg1-8+etch1 of cyrus-sasl2.

For the stable distribution (lenny), this problem has been fixed in
version 2.1.22.dfsg1-23+lenny1 of cyrus-sasl2 and cyrus-sasl2-heimdal."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:cyrus-sasl2-heimdal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/06/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"cyrus-sasl2", reference:"2.1.22.dfsg1-8+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-sasl2-dbg", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-sasl2-doc", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"cyrus-sasl2-heimdal-dbg", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-2", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-dev", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-modules", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-modules-gssapi-heimdal", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-modules-gssapi-mit", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-modules-ldap", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-modules-otp", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsasl2-modules-sql", reference:"2.1.22.dfsg1-23+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"sasl2-bin", reference:"2.1.22.dfsg1-23+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
