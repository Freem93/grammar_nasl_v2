#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-397. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(15234);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2013/05/18 00:11:34 $");

  script_cve_id("CVE-2003-0901");
  script_bugtraq_id(8741);
  script_xref(name:"DSA", value:"397");

  script_name(english:"Debian DSA-397-1 : postgresql - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Tom Lane discovered a buffer overflow in the to_ascii function in
PostgreSQL. This allows remote attackers to execute arbitrary code on
the host running the database."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2003/dsa-397"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the postgresql package.

For the stable distribution (woody) this problem has been fixed in
version 7.2.1-2woody4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2003/11/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2004/09/29");
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
if (deb_check(release:"3.0", prefix:"libecpg3", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libpgperl", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libpgsql2", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"libpgtcl", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"odbc-postgresql", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"pgaccess", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-client", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-contrib", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-dev", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"postgresql-doc", reference:"7.2.1-2woody4")) flag++;
if (deb_check(release:"3.0", prefix:"python-pygresql", reference:"7.2.1-2woody4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
