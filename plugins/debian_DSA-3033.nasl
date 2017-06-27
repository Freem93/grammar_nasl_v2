#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3033. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(77880);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2016/05/05 16:01:11 $");

  script_cve_id("CVE-2014-1568");
  script_bugtraq_id(70116);
  script_osvdb_id(112036);
  script_xref(name:"DSA", value:"3033");

  script_name(english:"Debian DSA-3033-1 : nss - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Antoine Delignat-Lavaud from Inria discovered an issue in the way NSS
(the Mozilla Network Security Service library) was parsing ASN.1 data
used in signatures, making it vulnerable to a signature forgery
attack.

An attacker could craft ASN.1 data to forge RSA certificates with a
valid certification chain to a trusted CA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/nss"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2014/dsa-3033"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the nss packages.

For the stable distribution (wheezy), this problem has been fixed in
version 2:3.14.5-1+deb7u2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:nss");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/09/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/09/26");
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
if (deb_check(release:"7.0", prefix:"libnss3", reference:"2:3.14.5-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-1d", reference:"2:3.14.5-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dbg", reference:"2:3.14.5-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-dev", reference:"2:3.14.5-1+deb7u2")) flag++;
if (deb_check(release:"7.0", prefix:"libnss3-tools", reference:"2:3.14.5-1+deb7u2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
