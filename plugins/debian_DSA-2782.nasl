#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2782. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(70533);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/02/16 15:43:10 $");

  script_cve_id("CVE-2013-4623", "CVE-2013-5914", "CVE-2013-5915");
  script_bugtraq_id(61764, 62771);
  script_osvdb_id(96240, 98018, 98049);
  script_xref(name:"DSA", value:"2782");

  script_name(english:"Debian DSA-2782-1 : polarssl - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues have been discovered in PolarSSL, a
lightweight crypto and SSL/TLS library :

  - CVE-2013-4623
    Jack Lloyd discovered a denial of service vulnerability
    in the parsing of PEM-encoded certificates.

  - CVE-2013-5914
    Paul Brodeur and TrustInSoft discovered a buffer
    overflow in the ssl_read_record() function, allowing the
    potential execution of arbitrary code.

  - CVE-2013-5915
    Cyril Arnaud and Pierre-Alain Fouque discovered timing
    attacks against the RSA implementation."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-4623"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-5914"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-5915"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/polarssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/polarssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2782"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the polarssl packages.

For the oldstable distribution (squeeze), these problems will be fixed
in version 1.2.9-1~deb6u1 soon (due to a technical limitation the
updates cannot be released synchronously).

For the stable distribution (wheezy), these problems have been fixed
in version 1.2.9-1~deb7u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:polarssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/10/20");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/10/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"libpolarssl-dev", reference:"1.2.9-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolarssl-runtime", reference:"1.2.9-1~deb6u1")) flag++;
if (deb_check(release:"6.0", prefix:"libpolarssl0", reference:"1.2.9-1~deb6u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpolarssl-dev", reference:"1.2.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpolarssl-runtime", reference:"1.2.9-1~deb7u1")) flag++;
if (deb_check(release:"7.0", prefix:"libpolarssl0", reference:"1.2.9-1~deb7u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
