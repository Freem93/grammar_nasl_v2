#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1880. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44745);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2009-0200", "CVE-2009-0201", "CVE-2009-2139");
  script_bugtraq_id(36200);
  script_osvdb_id(57658, 57659, 57860);
  script_xref(name:"DSA", value:"1880");

  script_name(english:"Debian DSA-1880-1 : openoffice.org - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the OpenOffice.org
office suite. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-0200
    Dyon Balding of Secunia Research has discovered a
    vulnerability, which can be exploited by opening a
    specially crafted Microsoft Word document.

  When reading a Microsoft Word document, a bug in the parser of
  sprmTDelete records can result in an integer underflow that may lead
  to heap-based buffer overflows.

  Successful exploitation may allow arbitrary code execution in the
  context of the OpenOffice.org process.

  - CVE-2009-0201
    Dyon Balding of Secunia Research has discovered a
    vulnerability, which can be exploited by opening a
    specially crafted Microsoft Word document.

  When reading a Microsoft Word document, a bug in the parser of
  sprmTDelete records can result in heap-based buffer overflows.

  Successful exploitation may allow arbitrary code execution in the
  context of the OpenOffice.org process.

  - CVE-2009-2139
    A vulnerability has been discovered in the parser of EMF
    files of OpenOffice/Go-oo 2.x and 3.x that can be
    triggered by a specially crafted document and lead to
    the execution of arbitrary commands the privileges of
    the user running OpenOffice.org/Go-oo.

  This vulnerability does not exist in the packages for oldstable,
  testing and unstable."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0200"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0201"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2139"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1880"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the Openoffice.org package.

For the old stable distribution (etch) these problems have been fixed
in version 2.0.4.dfsg.2-7etch7.

For the stable distribution (lenny) these problems have been fixed in
version 2.4.1+dfsg-1+lenny3 and higher."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(94, 119, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"broffice.org", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"libmythes-dev", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-base", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-calc", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-common", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-core", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dbg", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dev", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dev-doc", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-draw", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-dtd-officedocument1.0", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-evolution", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-filter-mobiledev", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-filter-so52", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gcj", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gnome", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gtk", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-gtk-gnome", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-cs", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-da", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-de", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-dz", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-en", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-en-gb", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-en-us", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-es", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-et", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-fr", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-hi-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-hu", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-it", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-ja", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-km", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-ko", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-nl", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-pl", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-pt-br", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-ru", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-sl", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-sv", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-zh-cn", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-help-zh-tw", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-impress", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-java-common", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-kde", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-af", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-as-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-be-by", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-bg", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-bn", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-br", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-bs", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ca", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-cs", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-cy", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-da", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-de", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-dz", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-el", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-en-gb", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-en-za", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-eo", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-es", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-et", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-fa", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-fi", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-fr", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ga", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-gu-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-he", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hi", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hi-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hr", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-hu", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-it", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ja", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ka", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-km", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ko", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ku", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-lo", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-lt", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-lv", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-mk", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ml-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nb", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ne", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nl", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nn", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-nr", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ns", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-or-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pa-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pl", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pt", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-pt-br", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ru", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-rw", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sk", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sl", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sr-cs", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ss", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-st", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-sv", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ta-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-te-in", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-tg", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-th", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-tn", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-tr", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ts", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-uk", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-ve", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-vi", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-xh", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-za", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-zh-cn", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-zh-tw", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-l10n-zu", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-math", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-officebean", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-qa-api-tests", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-qa-tools", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"openoffice.org-writer", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"python-uno", reference:"2.0.4.dfsg.2-7etch6")) flag++;
if (deb_check(release:"4.0", prefix:"ttf-opensymbol", reference:"2.0.4.dfsg.2-7etch7")) flag++;
if (deb_check(release:"5.0", prefix:"broffice.org", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"cli-uno-bridge", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libmythes-dev", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-basetypes1.0-cil", reference:"1.0.10.0+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-cppuhelper1.0-cil", reference:"1.0.13.0+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-types1.1-cil", reference:"1.1.13.0+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-ure1.0-cil", reference:"1.0.13.0+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"mozilla-openoffice.org", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-base", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-base-core", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-calc", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-common", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-core", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dbg", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dev", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dev-doc", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-draw", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dtd-officedocument1.0", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-emailmerge", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-evolution", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-filter-binfilter", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-filter-mobiledev", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-gcj", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-gnome", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-gtk", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-headless", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-cs", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-da", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-de", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-dz", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-en-gb", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-en-us", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-es", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-et", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-eu", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-fr", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-gl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-hi-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-hu", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-it", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-ja", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-km", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-ko", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-nl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-pl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-pt", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-pt-br", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-ru", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-sl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-sv", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-zh-cn", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-zh-tw", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-impress", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-java-common", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-kde", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-af", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ar", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-as-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-be-by", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-bg", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-bn", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-br", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-bs", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ca", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-cs", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-cy", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-da", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-de", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-dz", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-el", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-en-gb", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-en-za", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-eo", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-es", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-et", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-eu", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-fa", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-fi", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-fr", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ga", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-gl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-gu-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-he", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-hi-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-hr", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-hu", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-it", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ja", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ka", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-km", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ko", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ku", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-lo", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-lt", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-lv", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-mk", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ml-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-mr-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nb", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ne", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nn", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nr", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ns", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-or-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pa-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pt", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pt-br", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ro", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ru", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-rw", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sk", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sl", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sr", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sr-cs", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ss", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-st", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sv", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ta-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-te-in", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-tg", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-th", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-tn", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-tr", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ts", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-uk", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-uz", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ve", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-vi", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-xh", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-za", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-zh-cn", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-zh-tw", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-zu", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-math", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-officebean", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-ogltrans", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-presentation-minimizer", reference:"1.0+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-qa-api-tests", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-qa-tools", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-report-builder", reference:"1.0.2+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-report-builder-bin", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-sdbc-postgresql", reference:"0.7.6+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-andromeda", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-crystal", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-hicontrast", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-industrial", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-tango", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-writer", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"python-uno", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"ttf-opensymbol", reference:"2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"ure", reference:"1.4+OOo2.4.1+dfsg-1+lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"ure-dbg", reference:"1.4+OOo2.4.1+dfsg-1+lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
