#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1564. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(32126);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:59 $");

  script_cve_id("CVE-2007-0540", "CVE-2007-3639", "CVE-2007-4153", "CVE-2007-4154");
  script_osvdb_id(40802, 46994, 46995);
  script_xref(name:"DSA", value:"1564");

  script_name(english:"Debian DSA-1564-1 : wordpress - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in WordPress, a
weblog manager. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2007-3639
    Insufficient input sanitising allowed for remote
    attackers to redirect visitors to external websites.

  - CVE-2007-4153
    Multiple cross-site scripting vulnerabilities allowed
    remote authenticated administrators to inject arbitrary
    web script or HTML.

  - CVE-2007-4154
    SQL injection vulnerability allowed allowed remote
    authenticated administrators to execute arbitrary SQL
    commands.

  - CVE-2007-0540
    WordPress allows remote attackers to cause a denial of
    service (bandwidth or thread consumption) via pingback
    service calls with a source URI that corresponds to a
    file with a binary content type, which is downloaded
    even though it cannot contain usable pingback data.

  - [no CVE name yet]

    Insufficient input sanitising caused an attacker with a
    normal user account to access the administrative
    interface."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-3639"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4153"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-4154"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-0540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2008/dsa-1564"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress package.

For the stable distribution (etch), these problems have been fixed in
version 2.0.10-1etch2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/05/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2008/05/02");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2008-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"wordpress", reference:"2.0.10-1etch2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
