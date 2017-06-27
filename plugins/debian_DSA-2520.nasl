#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2520. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(61401);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2015/02/16 15:37:38 $");

  script_cve_id("CVE-2012-2665");
  script_bugtraq_id(54769);
  script_osvdb_id(84440, 84441, 84442);
  script_xref(name:"DSA", value:"2520");

  script_name(english:"Debian DSA-2520-1 : openoffice.org - Multiple heap-based buffer overflows");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Timo Warns from PRE-CERT discovered multiple heap-based buffer
overflows in OpenOffice.org, an office productivity suite. The issues
lies in the XML manifest encryption tag parsing code. Using specially
crafted files, an attacker can cause application crash and could cause
arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/openoffice.org"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2520"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openoffice.org packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1:3.2.1-11+squeeze7.

openoffice.org package has been replaced by libreoffice in testing
(wheezy) and unstable (sid) distributions."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/08/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"broffice.org", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"cli-uno-bridge", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libuno-cli-basetypes1.0-cil", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libuno-cli-cppuhelper1.0-cil", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libuno-cli-oootypes1.0-cil", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libuno-cli-ure1.0-cil", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"libuno-cli-uretypes1.0-cil", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"mozilla-openoffice.org", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-base", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-base-core", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-calc", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-common", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-core", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-dbg", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-dev", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-dev-doc", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-draw", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-dtd-officedocument1.0", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-emailmerge", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-evolution", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-filter-binfilter", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-filter-mobiledev", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-gcj", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-gnome", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-gtk", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-ca", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-cs", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-da", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-de", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-dz", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-el", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-en-gb", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-en-us", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-es", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-et", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-eu", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-fi", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-fr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-gl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-hi-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-hu", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-it", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-ja", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-km", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-ko", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-nl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-om", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-pl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-pt", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-pt-br", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-ru", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-sl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-sv", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-zh-cn", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-help-zh-tw", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-impress", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-java-common", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-kde", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-af", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ar", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-as", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-as-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ast", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-be-by", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-bg", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-bn", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-br", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-bs", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ca", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-cs", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-cy", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-da", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-de", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-dz", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-el", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-en-gb", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-en-za", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-eo", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-es", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-et", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-eu", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-fa", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-fi", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-fr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ga", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-gl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-gu", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-gu-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-he", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-hi-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-hr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-hu", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-id", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-it", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ja", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ka", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-km", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ko", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ku", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-lt", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-lv", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-mk", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ml", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ml-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-mn", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-mr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-mr-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-nb", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ne", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-nl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-nn", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-nr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ns", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-oc", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-om", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-or", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-or-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-pa-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-pl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-pt", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-pt-br", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ro", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ru", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-rw", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-si", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-sk", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-sl", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-sr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ss", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-st", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-sv", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ta", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ta-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-te", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-te-in", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-tg", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-th", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-tn", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-tr", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ts", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ug", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-uk", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-uz", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-ve", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-vi", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-xh", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-za", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-zh-cn", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-zh-tw", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-l10n-zu", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-math", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-mysql-connector", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-officebean", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-ogltrans", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-pdfimport", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-presentation-minimizer", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-presenter-console", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-report-builder", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-report-builder-bin", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-sdbc-postgresql", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-andromeda", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-crystal", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-galaxy", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-hicontrast", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-industrial", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-oxygen", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-style-tango", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-wiki-publisher", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"openoffice.org-writer", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"python-uno", reference:"1:3.2.1-11+squeeze7")) flag++;
if (deb_check(release:"6.0", prefix:"ttf-opensymbol", reference:"1:3.2.1-11+squeeze7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
