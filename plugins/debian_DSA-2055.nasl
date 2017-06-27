#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2055. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(46830);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/08/24 14:07:49 $");

  script_cve_id("CVE-2010-0395");
  script_bugtraq_id(40599);
  script_osvdb_id(65203);
  script_xref(name:"DSA", value:"2055");

  script_name(english:"Debian DSA-2055-1 : openoffice.org - macro execution");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"It was discovered that OpenOffice.org, a full-featured office
productivity suite that provides a near drop-in replacement for
Microsoft(r) Office, is not properly handling python macros embedded in
an office document. This allows an attacker to perform user-assisted
execution of arbitrary code in certain use cases of the python macro
viewer component."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2055"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openoffice.org packages.

For the stable distribution (lenny), this problem has been fixed in
version 1:2.4.1+dfsg-1+lenny7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/06/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/08");
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
if (deb_check(release:"5.0", prefix:"broffice.org", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"cli-uno-bridge", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libmythes-dev", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-basetypes1.0-cil", reference:"1:1.0.10.0+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-cppuhelper1.0-cil", reference:"1:1.0.13.0+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-types1.1-cil", reference:"1:1.1.13.0+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"libuno-cli-ure1.0-cil", reference:"1:1.0.13.0+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"mozilla-openoffice.org", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-base", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-base-core", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-calc", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-common", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-core", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dbg", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dev", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dev-doc", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-draw", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-dtd-officedocument1.0", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-emailmerge", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-evolution", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-filter-binfilter", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-filter-mobiledev", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-gcj", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-gnome", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-gtk", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-headless", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-cs", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-da", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-de", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-dz", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-en-gb", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-en-us", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-es", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-et", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-eu", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-fr", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-gl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-hi-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-hu", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-it", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-ja", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-km", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-ko", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-nl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-pl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-pt", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-pt-br", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-ru", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-sl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-sv", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-zh-cn", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-help-zh-tw", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-impress", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-java-common", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-kde", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-af", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ar", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-as-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-be-by", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-bg", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-bn", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-br", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-bs", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ca", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-cs", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-cy", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-da", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-de", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-dz", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-el", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-en-gb", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-en-za", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-eo", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-es", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-et", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-eu", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-fa", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-fi", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-fr", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ga", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-gl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-gu-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-he", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-hi-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-hr", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-hu", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-it", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ja", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ka", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-km", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ko", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ku", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-lo", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-lt", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-lv", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-mk", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ml-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-mr-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nb", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ne", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nn", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-nr", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ns", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-or-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pa-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pt", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-pt-br", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ro", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ru", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-rw", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sk", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sl", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sr", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sr-cs", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ss", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-st", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-sv", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ta-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-te-in", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-tg", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-th", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-tn", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-tr", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ts", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-uk", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-uz", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-ve", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-vi", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-xh", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-za", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-zh-cn", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-zh-tw", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-l10n-zu", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-math", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-officebean", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-ogltrans", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-presentation-minimizer", reference:"1:1.0+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-qa-api-tests", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-qa-tools", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-report-builder", reference:"1:1.0.2+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-report-builder-bin", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-sdbc-postgresql", reference:"1:0.7.6+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-andromeda", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-crystal", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-hicontrast", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-industrial", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-style-tango", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"openoffice.org-writer", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"python-uno", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"ttf-opensymbol", reference:"1:2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"ure", reference:"1:1.4+OOo2.4.1+dfsg-1+lenny7")) flag++;
if (deb_check(release:"5.0", prefix:"ure-dbg", reference:"1:1.4+OOo2.4.1+dfsg-1+lenny7")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
