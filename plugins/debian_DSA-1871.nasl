#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1871. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44736);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:52 $");

  script_cve_id("CVE-2008-1502", "CVE-2008-4106", "CVE-2008-4769", "CVE-2008-4796", "CVE-2008-5113", "CVE-2008-6762", "CVE-2008-6767", "CVE-2009-2334", "CVE-2009-2851", "CVE-2009-2853", "CVE-2009-2854");
  script_bugtraq_id(28599, 31068, 31887, 35584, 35935);
  script_osvdb_id(44591);
  script_xref(name:"DSA", value:"1871");

  script_name(english:"Debian DSA-1871-1 : wordpress - several vulnerabilities ");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in wordpress, weblog
manager. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2008-6762
    It was discovered that wordpress is prone to an open
    redirect vulnerability which allows remote attackers to
    conduct phishing attacks.

  - CVE-2008-6767
    It was discovered that remote attackers had the ability
    to trigger an application upgrade, which could lead to a
    denial of service attack.

  - CVE-2009-2334
    It was discovered that wordpress lacks authentication
    checks in the plugin configuration, which might leak
    sensitive information.

  - CVE-2009-2854
    It was discovered that wordpress lacks authentication
    checks in various actions, thus allowing remote
    attackers to produce unauthorised edits or additions.

  - CVE-2009-2851
    It was discovered that the administrator interface is
    prone to a cross-site scripting attack.

  - CVE-2009-2853
    It was discovered that remote attackers can gain
    privileges via certain direct requests.

  - CVE-2008-1502
    It was discovered that the _bad_protocol_once function
    in KSES, as used by wordpress, allows remote attackers
    to perform cross-site scripting attacks.

  - CVE-2008-4106
    It was discovered that wordpress lacks certain checks
    around user information, which could be used by
    attackers to change the password of a user.

  - CVE-2008-4769
    It was discovered that the get_category_template
    function is prone to a directory traversal
    vulnerability, which could lead to the execution of
    arbitrary code.

  - CVE-2008-4796
    It was discovered that the _httpsrequest function in the
    embedded snoopy version is prone to the execution of
    arbitrary commands via shell metacharacters in https
    URLs.

  - CVE-2008-5113
    It was discovered that wordpress relies on the REQUEST
    superglobal array in certain dangerous situations, which
    makes it easier to perform attacks via crafted cookies."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=531736"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=536724"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=500115"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504234"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=504771"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6762"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-6767"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2334"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2854"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2851"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-2853"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-1502"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4106"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4769"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4796"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5113"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1871"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the wordpress packages.

For the oldstable distribution (etch), these problems have been fixed
in version 2.0.10-1etch4.

For the stable distribution (lenny), these problems have been fixed in
version 2.5.1-11+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"d2_elliot_name", value:"Moodle <= 1.8.4 RCE");
  script_set_attribute(attribute:"exploit_framework_d2_elliot", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20, 22, 59, 79, 94, 264, 287, 352);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:wordpress");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"4.0", prefix:"wordpress", reference:"2.0.10-1etch4")) flag++;
if (deb_check(release:"5.0", prefix:"wordpress", reference:"2.5.1-11+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
