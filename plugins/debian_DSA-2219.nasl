#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2219. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(53477);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-1425");
  script_bugtraq_id(47135);
  script_osvdb_id(72303);
  script_xref(name:"DSA", value:"2219");

  script_name(english:"Debian DSA-2219-1 : xmlsec1 - arbitrary file overwrite");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Nicolas Gregoire discovered that the XML Security Library xmlsec
allowed remote attackers to create or overwrite arbitrary files
through specially crafted XML files using the libxslt output extension
and a ds:Transform element during signature verification."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=620560"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/xmlsec1"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2219"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the xmlsec1 packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1.2.9-5+lenny1.

For the stable distribution (squeeze), this problem has been fixed in
version 1.2.14-1+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xmlsec1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/04/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/04/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"xmlsec1", reference:"1.2.9-5+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"libxmlsec1", reference:"1.2.14-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxmlsec1-dev", reference:"1.2.14-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxmlsec1-gnutls", reference:"1.2.14-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxmlsec1-nss", reference:"1.2.14-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libxmlsec1-openssl", reference:"1.2.14-1+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"xmlsec1", reference:"1.2.14-1+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
