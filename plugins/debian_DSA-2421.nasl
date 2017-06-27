#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2421. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(58172);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-4308", "CVE-2011-4584", "CVE-2011-4585", "CVE-2011-4586", "CVE-2011-4587", "CVE-2011-4588", "CVE-2012-0792", "CVE-2012-0793", "CVE-2012-0794", "CVE-2012-0795", "CVE-2012-0796");
  script_bugtraq_id(50283, 50923, 51450, 51840);
  script_osvdb_id(76695, 77503, 77504, 78347, 79774, 79775, 79776, 79781, 79782, 79783);
  script_xref(name:"DSA", value:"2421");

  script_name(english:"Debian DSA-2421-1 : moodle - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security issues have been fixed in Moodle, a course management
system for online learning :

  - CVE-2011-4308 / CVE-2012-0792
    Rossiani Wijaya discovered an information leak in
    mod/forum/user.php.

  - CVE-2011-4584
    MNet authentication didn't prevent a user using 'Login
    as' from jumping to a remove MNet SSO.

  - CVE-2011-4585
    Darragh Enright discovered that the change password form
    was send in over plain HTTP even if httpslogin was set
    to 'true'.

  - CVE-2011-4586
    David Michael Evans and German Sanchez Gances discovered
    CRLF injection/HTTP response splitting vulnerabilities
    in the Calendar module.

  - CVE-2011-4587
    Stephen Mc Guiness discovered empty passwords could be
    entered in some circumstances.

  - CVE-2011-4588
    Patrick McNeill discovered that IP address restrictions
    could be bypassed in MNet.

  - CVE-2012-0796
    Simon Coggins discovered that additional information
    could be injected into mail headers.

  - CVE-2012-0795
    John Ehringer discovered that email addresses were
    insufficiently validated.

  - CVE-2012-0794
    Rajesh Taneja discovered that cookie encryption used a
    fixed key.

  - CVE-2012-0793
    Eloy Lafuente discovered that profile images were
    insufficiently protected. A new configuration option
    'forceloginforprofileimages' was introduced for that."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4308"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0792"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4585"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4586"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4587"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-4588"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0795"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0794"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0793"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/moodle"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2421"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the moodle packages.

For the stable distribution (squeeze), this problem has been fixed in
version 1.9.9.dfsg2-2.1+squeeze3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:moodle");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/02/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/03/01");
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
if (deb_check(release:"6.0", prefix:"moodle", reference:"1.9.9.dfsg2-2.1+squeeze3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
