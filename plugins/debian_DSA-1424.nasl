#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1424. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29259);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-5947", "CVE-2007-5959", "CVE-2007-5960");
  script_bugtraq_id(26385, 26589, 26593);
  script_osvdb_id(38463, 38867, 38868);
  script_xref(name:"DSA", value:"1424");

  script_name(english:"Debian DSA-1424-1 : iceweasel - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Iceweasel
web browser, an unbranded version of the Firefox browser. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2007-5947
    Jesse Ruderman and Petko D. Petkov discovered that the
    URI handler for JAR archives allows cross-site
    scripting.

  - CVE-2007-5959
    Several crashes in the layout engine were discovered,
    which might allow the execution of arbitrary code.

  - CVE-2007-5960
    Gregory Fleischer discovered a race condition in the
    handling of the 'window.location' property, which might
    lead to cross-site request forgery.

The Mozilla products in the oldstable distribution (sarge) are no
longer supported with security updates."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5959"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5960"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1424"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (etch) these problems have been fixed in
version 2.0.0.10-0etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(22, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2007/12/11");
  script_set_attribute(attribute:"vuln_publication_date", value:"2007/11/09");
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
if (deb_check(release:"4.0", prefix:"firefox", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-dom-inspector", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"firefox-gnome-support", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dbg", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-dom-inspector", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"iceweasel-gnome-support", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-dom-inspector", reference:"2.0.0.10-0etch1")) flag++;
if (deb_check(release:"4.0", prefix:"mozilla-firefox-gnome-support", reference:"2.0.0.10-0etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
