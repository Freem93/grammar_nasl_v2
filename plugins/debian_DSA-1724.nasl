#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1724. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(35691);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-5153", "CVE-2009-0500", "CVE-2009-0502");
  script_bugtraq_id(32402, 33610);
  script_osvdb_id(49987, 54086, 54088);
  script_xref(name:"DSA", value:"1724");

  script_name(english:"Debian DSA-1724-1 : moodle - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Moodle, an online
course management system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-0500
    It was discovered that the information stored in the log
    tables was not properly sanitized, which could allow
    attackers to inject arbitrary web code.

  - CVE-2009-0502
    It was discovered that certain input via the 'Login as'
    function was not properly sanitised leading to the
    injection of arbitrary web script.

  - CVE-2008-5153
    Dmitry E. Oboukhov discovered that the SpellCheker
    plugin creates temporary files insecurely, allowing a
    denial of service attack. Since the plugin was unused,
    it is removed in this update."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=514284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0500"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1724"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moodle package.

For the stable distribution (etch) these problems have been fixed in
version 1.6.3-2+etch2.

For the testing (lenny) distribution these problems have been fixed in
version 1.8.2.dfsg-3+lenny1.

For the unstable (sid) distribution these problems have been fixed in
version 1.8.2.dfsg-4."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(59, 79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/02/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/02/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"moodle", reference:"1.6.3-2+etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
