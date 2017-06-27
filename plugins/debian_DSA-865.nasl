#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-865. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(20020);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-3069");
  script_osvdb_id(19596);
  script_xref(name:"DSA", value:"865");

  script_name(english:"Debian DSA-865-1 : hylafax - insecure temporary files");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Javier Fernandez-Sanguino Pena discovered that several scripts of
the hylafax suite, a flexible client/server fax software, create
temporary files and directories in an insecure fashion, leaving them
vulnerable to symlink exploits."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-865"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the hylafax packages.

For the old stable distribution (woody) this problem has been fixed in
version 4.1.1-3.2.

For the stable distribution (sarge) this problem has been fixed in
version 4.2.1-5sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:N");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hylafax");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2005/10/19");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/09/21");
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
if (deb_check(release:"3.0", prefix:"hylafax-client", reference:"4.1.1-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-doc", reference:"4.1.1-3.2")) flag++;
if (deb_check(release:"3.0", prefix:"hylafax-server", reference:"4.1.1-3.2")) flag++;
if (deb_check(release:"3.1", prefix:"hylafax-client", reference:"4.2.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hylafax-doc", reference:"4.2.1-5sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"hylafax-server", reference:"4.2.1-5sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:deb_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
