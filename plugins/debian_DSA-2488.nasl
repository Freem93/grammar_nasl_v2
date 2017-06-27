#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2488. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(59766);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/04/28 18:23:48 $");

  script_cve_id("CVE-2012-1937", "CVE-2012-1940", "CVE-2012-1947");
  script_osvdb_id(82667, 82669, 82676);
  script_xref(name:"DSA", value:"2488");

  script_name(english:"Debian DSA-2488-1 : iceweasel - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in Iceweasel, a web
browser based on Firefox. The included XULRunner library provides
rendering services for several other applications included in Debian.

  - CVE-2012-1937
    Mozilla developers discovered several memory corruption
    bugs, which may lead to the execution of arbitrary code.

  - CVE-2012-1940
    Abhishek Arya discovered a use-after-free problem when
    working with column layout with absolute positioning in
    a container that changes size, which may lead to the
    execution of arbitrary code.

  - CVE-2012-1947
    Abhishek Arya discovered a heap buffer overflow in utf16
    to latin1 character set conversion, allowing to execute
    arbitrary code.

Note: We'd like to advise users of Iceweasel's 3.5 branch in Debian
stable to consider to upgrade to the Iceweasel 10.0 ESR (Extended
Support Release) which is now available in Debian Backports. Although
Debian will continue to support Iceweasel 3.5 in stable with security
updates, this can only be done on a best effort base as upstream
provides no such support anymore. On top of that, the 10.0 branch adds
proactive security features to the browser."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1937"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1940"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-1947"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/iceweasel"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2488"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the iceweasel packages.

For the stable distribution (squeeze), this problem has been fixed in
version 3.5.16-16."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:iceweasel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/06/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/06/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"iceweasel", reference:"3.5.16-16")) flag++;
if (deb_check(release:"6.0", prefix:"iceweasel-dbg", reference:"3.5.16-16")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
