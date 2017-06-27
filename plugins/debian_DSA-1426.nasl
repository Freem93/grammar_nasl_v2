#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1426. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29261);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2007-3388", "CVE-2007-4137");
  script_osvdb_id(39384, 39385);
  script_xref(name:"DSA", value:"1426");

  script_name(english:"Debian DSA-1426-1 : qt-x11-free - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local/remote vulnerabilities have been discovered in the Qt
GUI library. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-3388
    Tim Brown and Dirk Muller discovered several format
    string vulnerabilities in the handling of error
    messages, which might lead to the execution of arbitrary
    code.

  - CVE-2007-4137
    Dirk Muller discovered an off-by-one buffer overflow in
    the Unicode handling, which might lead to the execution
    of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3388"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4137"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1426"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the qt-x11-free packages.

For the old stable distribution (sarge), these problems have been
fixed in version 3:3.3.4-3sarge3. Packages for m68k will be provided
later.

For the stable distribution (etch), these problems have been fixed in
version 3:3.3.7-4etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:qt-x11-free");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2007-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"libqt3-compat-headers", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-dev", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-headers", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-i18n", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3-mt-dev", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-ibase", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-ibase", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-mysql", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-odbc", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-psql", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mt-sqlite", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-mysql", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-odbc", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-psql", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"libqt3c102-sqlite", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-apps-dev", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-assistant", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-designer", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-dev-tools", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-dev-tools-compat", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-dev-tools-embedded", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-doc", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-examples", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-linguist", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"3.1", prefix:"qt3-qtconfig", reference:"3:3.3.4-3sarge3")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-compat-headers", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-headers", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-i18n", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt-dev", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt-ibase", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt-mysql", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt-odbc", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt-psql", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"libqt3-mt-sqlite", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt-x11-free-dbg", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-apps-dev", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-assistant", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-designer", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-dev-tools", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-dev-tools-compat", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-dev-tools-embedded", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-doc", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-examples", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-linguist", reference:"3:3.3.7-4etch1")) flag++;
if (deb_check(release:"4.0", prefix:"qt3-qtconfig", reference:"3:3.3.7-4etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
