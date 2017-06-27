#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2309. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56179);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-1945");
  script_bugtraq_id(47888);
  script_osvdb_id(74632);
  script_xref(name:"DSA", value:"2309");

  script_name(english:"Debian DSA-2309-1 : openssl - compromised certificate authority");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several fraudulent SSL certificates have been found in the wild issued
by the DigiNotar Certificate Authority, obtained through a security
compromise of said company. After further updates on this incident, it
has been determined that all of DigiNotar's signing certificates can
no longer be trusted. Debian, like other software distributors and
vendors, has decided to distrust all of DigiNotar's CAs. In this
update, this is done in the crypto library (a component of the OpenSSL
toolkit) by marking such certificates as revoked. Any application that
uses said component should now reject certificates signed by
DigiNotar. Individual applications may allow users to override the
validation failure. However, making exceptions is highly discouraged
and should be carefully verified.

Additionally, a vulnerability has been found in the ECDHE_ECDS cipher
where timing attacks make it easier to determine private keys. The
Common Vulnerabilities and Exposures project identifies it as
CVE-2011-1945."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1945"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openssl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2309"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openssl packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 0.9.8g-15+lenny12.

For the stable distribution (squeeze), these problems have been fixed
in version 0.9.8o-4squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openssl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/09/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/09/14");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"openssl", reference:"0.9.8g-15+lenny12")) flag++;
if (deb_check(release:"6.0", prefix:"libcrypto0.9.8-udeb", reference:"0.9.8o-4squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libssl-dev", reference:"0.9.8o-4squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8", reference:"0.9.8o-4squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libssl0.9.8-dbg", reference:"0.9.8o-4squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"openssl", reference:"0.9.8o-4squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
