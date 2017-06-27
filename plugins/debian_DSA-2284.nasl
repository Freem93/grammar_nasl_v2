#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2284. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55674);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/09/03 13:42:46 $");

  script_cve_id("CVE-2011-1411");
  script_osvdb_id(74167);
  script_xref(name:"DSA", value:"2284");

  script_name(english:"Debian DSA-2284-1 : opensaml2 - implementation error");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Juraj Somorovsky, Andreas Mayer, Meiko Jensen, Florian Kohlar, Marco
Kampmann and Joerg Schwenk discovered that Shibboleth, a federated web
single sign-on system is vulnerable to XML signature wrapping attacks.
More details can be found in the Shibboleth advisory."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://shibboleth.internet2.edu/security-advisories.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/opensaml2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2284"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the oldstable distribution (lenny), this problem has been fixed in
version 2.0-2+lenny3.

For the stable distribution (squeeze), this problem has been fixed in
version 2.3-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:opensaml2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/26");
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
if (deb_check(release:"5.0", prefix:"opensaml2", reference:"2.0-2+lenny3")) flag++;
if (deb_check(release:"6.0", prefix:"libsaml2-dev", reference:"2.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libsaml2-doc", reference:"2.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libsaml6", reference:"2.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"opensaml2-schemas", reference:"2.3-2+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"opensaml2-tools", reference:"2.3-2+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
