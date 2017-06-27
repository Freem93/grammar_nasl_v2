#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-351. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15188);
  script_version("$Revision: 1.20 $");
  script_cvs_date("$Date: 2014/08/13 14:23:42 $");

  script_cve_id("CVE-2003-0442");
  script_bugtraq_id(7761);
  script_xref(name:"DSA", value:"351");

  script_name(english:"Debian DSA-351-1 : php4 - XSS");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The transparent session ID feature in the php4 package does not
properly escape user-supplied input before inserting it into the
generated HTML page. An attacker could use this vulnerability to
execute embedded scripts within the context of the generated page."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugs.debian.org/200736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-351"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (woody) this problem has been fixed in
version 4:4.1.2-6woody3.

We recommend that you update your php4 package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:php4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/07/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2004-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"caudium-php4", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-cgi", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-curl", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-dev", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-domxml", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-gd", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-imap", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-ldap", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mcal", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mhash", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-mysql", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-odbc", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-pear", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-recode", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-snmp", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-sybase", reference:"4:4.1.2-6woody3")) flag++;
if (deb_check(release:"3.0", prefix:"php4-xslt", reference:"4:4.1.2-6woody3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
