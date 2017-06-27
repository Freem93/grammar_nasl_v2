#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2157. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51862);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2013/05/17 23:58:35 $");

  script_cve_id("CVE-2010-4015");
  script_bugtraq_id(46084);
  script_xref(name:"DSA", value:"2157");

  script_name(english:"Debian DSA-2157-1 : postgresql-8.3, postgresql-8.4, postgresql-9.0 - buffer overflow");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that PostgreSQL's intarray contrib module does not
properly handle integers with a large number of digits, leading to a
server crash and potentially arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2157"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the PostgreSQL packages.

For the stable distribution (lenny), this problem has been fixed in
version 8.3.14-0lenny1 of the postgresql-8.3 package.

The updates also include reliability improvements; for details see the
respective changelogs."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.3");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-8.4");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:postgresql-9.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/02/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/02/04");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"postgresql-8.3", reference:"8.3.14-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-8.4", reference:"8.3.14-0lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"postgresql-9.0", reference:"8.3.14-0lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
