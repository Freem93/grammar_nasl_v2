#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-906. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22772);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2016/05/26 16:04:30 $");

  script_cve_id("CVE-2005-3354");
  script_osvdb_id(20675);
  script_xref(name:"DSA", value:"906");

  script_name(english:"Debian DSA-906-1 : sylpheed - buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Colin Leroy discovered several buffer overflows in a number of
importer routines in sylpheed, a light-weight e-mail client with GTK+,
that could lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=338436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2005/dsa-906"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sylpheed package.

The following matrix explains which versions fix this vulnerability

                       old stable (woody)   stable (sarge)       unstable (sid)       
  sylpheed             0.7.4-4woody1        1.0.4-1sarge1        2.0.4-1              
  sylpheed-gtk1        n/a                  n/a                  1.0.6-1              
  sylpheed-claws       0.7.4claws-3woody1   1.0.4-1sarge1        1.0.5-2              
  sylpheed-claws-gtk2  n/a                  n/a                  1.9.100-1"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sylpheed");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/11/22");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.0", prefix:"sylpheed", reference:"0.7.4-4woody1")) flag++;
if (deb_check(release:"3.0", prefix:"sylpheed-doc", reference:"0.7.4-4woody1")) flag++;
if (deb_check(release:"3.1", prefix:"sylpheed", reference:"1.0.4-1sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"sylpheed-i18n", reference:"1.0.4-1sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
