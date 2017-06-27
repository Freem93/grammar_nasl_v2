#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1419. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29226);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2013/05/17 23:45:44 $");

  script_cve_id("CVE-2007-4575");
  script_osvdb_id(40548);
  script_xref(name:"DSA", value:"1419");

  script_name(english:"Debian DSA-1419-1 : openoffice.org - programming error");
  script_summary(english:"Checks dpkg output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A vulnerability has been discovered in HSQLDB, the default database
engine shipped with OpenOffice.org. This could result in the execution
of arbitrary Java code embedded in a OpenOffice.org database document
with the user's privilege. This update requires an update of both
openoffice.org and hsqldb."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1419"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the OpenOffice.org and hsqldb packages.

The old stable distribution (sarge) is not affected by this problem.

For the stable distribution (etch) this problem has been fixed in
version 2.0.4.dfsg.2-7etch4 of OpenOffice.org and in version
1.8.0.7-1etch1 of hsqldb."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:hsqldb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/07");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2013 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"broffice.org", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"hsqldb-server", reference:"1.8.0.7-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libhsqldb-java", reference:"1.8.0.7-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libhsqldb-java-doc", reference:"1.8.0.7-1etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libmythes-dev", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-base", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-calc", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-common", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-core", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dbg", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dev", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dev-doc", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-draw", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dtd-officedocument1.0", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-evolution", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-filter-mobiledev", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-filter-so52", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gcj", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gnome", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gtk", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gtk-gnome", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-cs", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-da", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-de", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-dz", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-en", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-en-gb", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-en-us", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-es", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-et", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-fr", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-hi-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-hu", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-it", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-ja", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-km", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-ko", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-nl", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-pl", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-pt-br", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-ru", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-sl", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-sv", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-zh-cn", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-zh-tw", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-impress", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-java-common", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-kde", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-af", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-as-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-be-by", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-bg", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-bn", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-br", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-bs", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ca", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-cs", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-cy", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-da", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-de", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-dz", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-el", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-en-gb", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-en-za", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-eo", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-es", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-et", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-fa", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-fi", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-fr", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ga", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-gu-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-he", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hi", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hi-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hr", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hu", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-it", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ja", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ka", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-km", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ko", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ku", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-lo", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-lt", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-lv", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-mk", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ml-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nb", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ne", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nl", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nn", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nr", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ns", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-or-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pa-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pl", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pt", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pt-br", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ru", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-rw", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sk", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sl", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sr-cs", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ss", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-st", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sv", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ta-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-te-in", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-tg", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-th", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-tn", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-tr", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ts", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-uk", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ve", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-vi", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-xh", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-za", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-zh-cn", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-zh-tw", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-zu", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-math", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-officebean", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-qa-api-tests", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-qa-tools", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-writer", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"python-uno", reference:"2.0.4.dfsg.2-7etch4")) flag++;
if (deb_check(release:"4.0", prefix:"ttf-opensymbol", reference:"2.0.4.dfsg.2-7etch4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
