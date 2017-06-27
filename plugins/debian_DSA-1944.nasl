#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1944. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44809);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/19 14:28:19 $");

  script_cve_id("CVE-2009-3585", "CVE-2009-4151");
  script_bugtraq_id(37162);
  script_osvdb_id(61116);
  script_xref(name:"DSA", value:"1944");

  script_name(english:"Debian DSA-1944-1 : request-tracker3.4 request-tracker3.6 - session hijack");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Mikal Gule discovered that request-tracker, an extensible
trouble-ticket tracking system, is prone to an attack, where an
attacker with access to the same domain can hijack a user's RT
session."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1944"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the request-tracker packages.

For the oldstable distribution (etch), this problem has been fixed in
version 3.6.1-4+etch1 of request-tracker3.6 and version 3.4.5-2+etch1
of request-tracker3.4.

For the stable distribution (lenny), this problem has been fixed in
version 3.6.7-5+lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(287);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker3.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:request-tracker3.6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"request-tracker3.4", reference:"3.4.5-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"request-tracker3.6", reference:"3.6.1-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt3.4-apache", reference:"3.4.5-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt3.4-apache2", reference:"3.4.5-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt3.4-clients", reference:"3.4.5-2+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt3.6-apache", reference:"3.6.1-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt3.6-apache2", reference:"3.6.1-4+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"rt3.6-clients", reference:"3.6.1-4+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"request-tracker3.6", reference:"3.6.7-5+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"rt3.6-apache2", reference:"3.6.7-5+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"rt3.6-clients", reference:"3.6.7-5+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"rt3.6-db-mysql", reference:"3.6.7-5+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"rt3.6-db-postgresql", reference:"3.6.7-5+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"rt3.6-db-sqlite", reference:"3.6.7-5+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
