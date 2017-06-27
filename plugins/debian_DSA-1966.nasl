#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1966. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44831);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/30 13:45:23 $");

  script_cve_id("CVE-2009-3237", "CVE-2009-3701", "CVE-2009-4363");
  script_bugtraq_id(37351);
  script_osvdb_id(58108, 58109, 61043, 61303, 61304, 61338);
  script_xref(name:"DSA", value:"1966");

  script_name(english:"Debian DSA-1966-1 : horde3 - insufficient input sanitising");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in horde3, the horde web
application framework. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2009-3237
    It has been discovered that horde3 is prone to
    cross-site scripting attacks via crafted number
    preferences or inline MIME text parts when using
    text/plain as MIME type. For lenny this issue was
    already fixed, but as an additional security precaution,
    the display of inline text was disabled in the
    configuration file.

  - CVE-2009-3701
    It has been discovered that the horde3 administration
    interface is prone to cross-site scripting attacks due
    to the use of the PHP_SELF variable. This issue can only
    be exploited by authenticated administrators.

  - CVE-2009-4363
    It has been discovered that horde3 is prone to several
    cross-site scripting attacks via crafted data:text/html
    values in HTML messages."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3237"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3701"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4363"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-1966"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the horde3 packages.

For the stable distribution (lenny), these problems have been fixed in
version 3.2.2+debian0-2+lenny2.

For the oldstable distribution (etch), these problems have been fixed
in version 3.1.3-4etch7."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:horde3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"horde3", reference:"3.1.3-4etch7")) flag++;
if (deb_check(release:"5.0", prefix:"horde3", reference:"3.2.2+debian0-2+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
