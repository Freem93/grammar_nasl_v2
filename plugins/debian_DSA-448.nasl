#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-448. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15285);
  script_version("$Revision: 1.19 $");
  script_cvs_date("$Date: 2016/07/05 14:10:48 $");

  script_cve_id("CVE-2004-0054", "CVE-2004-0056", "CVE-2004-0097", "CVE-2004-2629", "CVE-2004-2758");
  script_bugtraq_id(9406);
  script_osvdb_id(3455, 140854);
  script_xref(name:"DSA", value:"448");

  script_name(english:"Debian DSA-448-1 : pwlib - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in pwlib, a library used to
aid in writing portable applications, whereby a remote attacker could
cause a denial of service or potentially execute arbitrary code. This
library is most notably used in several applications implementing the
H.323 teleconferencing protocol, including the OpenH323 suite,
gnomemeeting and asterisk."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/233888"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2004/dsa-448"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the current stable distribution (woody) this problem has been
fixed in version 1.2.5-5woody1.

We recommend that you update your pwlib package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:U/RC:UC");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:pwlib");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2004/02/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/01/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"asnparser", reference:"1.2.5-5woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libpt-1.2.0", reference:"1.2.5-5woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libpt-dbg", reference:"1.2.5-5woody1")) flag++;
if (deb_check(release:"3.0", prefix:"libpt-dev", reference:"1.2.5-5woody1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
