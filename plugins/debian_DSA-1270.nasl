#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1270. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(24879);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2014/05/03 11:14:58 $");

  script_cve_id("CVE-2007-0002", "CVE-2007-0238", "CVE-2007-0239");
  script_osvdb_id(33971, 33972);
  script_xref(name:"DSA", value:"1270");

  script_name(english:"Debian DSA-1270-2 : openoffice.org - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in
OpenOffice.org, the free office suite. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2007-0002
    iDefense reported several integer overflow bugs in
    libwpd, a library for handling WordPerfect documents
    that is included in OpenOffice.org. Attackers are able
    to exploit these with carefully crafted WordPerfect
    files that could cause an application linked with libwpd
    to crash or possibly execute arbitrary code.

  - CVE-2007-0238
    Next Generation Security discovered that the StarCalc
    parser in OpenOffice.org contains an easily exploitable
    stack overflow that could be used by a specially crafted
    document to execute arbitrary code.

  - CVE-2007-0239
    It has been reported that OpenOffice.org does not escape
    shell meta characters and is hence vulnerable to execute
    arbitrary shell commands via a specially crafted
    document after the user clicked to a prepared link.

This updated advisory only provides packages for the upcoming etch
release alias Debian GNU/Linux 4.0."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0002"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0239"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1270"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the OpenOffice.org packages.

For the stable distribution (sarge) these problems have been fixed in
version 1.1.3-9sarge6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"plugin_publication_date", value:"2007/03/26");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"openoffice.org", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-bin", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-dev", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-evolution", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-gtk-gnome", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-kde", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-af", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-ar", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-ca", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-cs", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-cy", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-da", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-de", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-el", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-en", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-es", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-et", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-eu", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-fi", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-fr", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-gl", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-he", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-hi", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-hu", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-it", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-ja", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-kn", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-ko", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-lt", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-nb", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-nl", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-nn", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-ns", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-pl", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-pt", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-pt-br", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-ru", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-sk", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-sl", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-sv", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-th", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-tn", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-tr", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-zh-cn", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-zh-tw", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-l10n-zu", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-mimelnk", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"openoffice.org-thesaurus-en-us", reference:"1.1.3-9sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ttf-opensymbol", reference:"1.1.3-9sarge6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
