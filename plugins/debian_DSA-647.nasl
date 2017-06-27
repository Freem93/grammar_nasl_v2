#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-647. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(16214);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/05/26 15:53:38 $");

  script_cve_id("CVE-2005-0004");
  script_osvdb_id(13013);
  script_xref(name:"DSA", value:"647");

  script_name(english:"Debian DSA-647-1 : mysql - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena from the Debian Security Audit Project
discovered a temporary file vulnerability in the mysqlaccess script of
MySQL that could allow an unprivileged user to let root overwrite
arbitrary files via a symlink attack and could also could unveil the
contents of a temporary file which might contain sensitive
information."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-647"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mysql packages.

For the stable distribution (woody) this problem has been fixed in
version 3.23.49-8.9."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mysql");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/01/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/01/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/01/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2005-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"libmysqlclient10", reference:"3.23.49-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"libmysqlclient10-dev", reference:"3.23.49-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-client", reference:"3.23.49-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-common", reference:"3.23.49-8.9")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-doc", reference:"3.23.49-8.5")) flag++;
if (deb_check(release:"3.0", prefix:"mysql-server", reference:"3.23.49-8.9")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
