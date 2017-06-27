#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-795. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(19565);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2013/05/18 00:15:59 $");

  script_cve_id("CVE-2005-2390");
  script_osvdb_id(18270, 18271);
  script_xref(name:"DSA", value:"795");

  script_name(english:"Debian DSA-795-2 : proftpd - potential code execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"infamous42md reported that proftpd suffers from two format string
vulnerabilities. In the first, a user with the ability to create a
directory could trigger the format string error if there is a proftpd
shutdown message configured to use the '%C', '%R', or '%U' variables.
In the second, the error is triggered if mod_sql is used to retrieve
messages from a database and if format strings have been inserted into
the database by a user with permission to do so."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-795"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the proftpd package.

The old stable distribution (woody) is not affected by these
vulnerabilities.

For the stable distribution (sarge) this problem has been fixed in
version 1.2.10-15sarge1. There was an error in the packages originally
prepared for i386, which was corrected in 1.2.10-15sarge1.0.1 for
i386."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:proftpd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2005/09/06");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/07/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"proftpd", reference:"1.2.10-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-common", reference:"1.2.10-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-doc", reference:"1.2.10-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-ldap", reference:"1.2.10-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-mysql", reference:"1.2.10-15sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"proftpd-pgsql", reference:"1.2.10-15sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
