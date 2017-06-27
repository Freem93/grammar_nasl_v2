#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1423. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(29258);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/12/06 20:12:50 $");

  script_cve_id("CVE-2007-5491", "CVE-2007-5492", "CVE-2007-5692", "CVE-2007-5693", "CVE-2007-5694", "CVE-2007-5695");
  script_osvdb_id(41110, 41355, 41356, 41357, 41358, 41359, 41581, 43604, 43760, 45516);
  script_xref(name:"DSA", value:"1423");

  script_name(english:"Debian DSA-1423-1 : sitebar - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in sitebar, a
web-based bookmark manager written in PHP. The Common Vulnerabilities
and Exposures project identifies the following problems :

  - CVE-2007-5491
    A directory traversal vulnerability in the translation
    module allows remote authenticated users to chmod
    arbitrary files to 0777 via '..' sequences in the 'lang'
    parameter.

  - CVE-2007-5492
    A static code injection vulnerability in the translation
    module allows a remote authenticated user to execute
    arbitrary PHP code via the 'value' parameter.

  - CVE-2007-5693
    An eval injection vulnerability in the translation
    module allows remote authenticated users to execute
    arbitrary PHP code via the'edit' parameter in an 'upd
    cmd' action.

  - CVE-2007-5694
    A path traversal vulnerability in the translation module
    allows remote authenticated users to read arbitrary
    files via an absolute path in the 'dir' parameter.

  - CVE-2007-5695
    An error in command.php allows remote attackers to
    redirect users to arbitrary websites via the 'forward'
    parameter in a 'Log In' action.

  - CVE-2007-5692
    Multiple cross site scripting flaws allow remote
    attackers to inject arbitrary script or HTML fragments
    into several scripts."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=447135"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=448690"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=448689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5491"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5492"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5693"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5695"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2007-5692"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2007/dsa-1423"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the sitebar package.

For the old stable distribution (sarge), these problems have been
fixed in version 3.2.6-7.1sarge1.

For the stable distribution (etch), these problems have been fixed in
version 3.3.8-7etch1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:C/I:C/A:C");
  script_cwe_id(22, 59, 79, 94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:sitebar");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/12/07");
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
if (deb_check(release:"3.1", prefix:"sitebar", reference:"3.2.6-7.1sarge1")) flag++;
if (deb_check(release:"4.0", prefix:"sitebar", reference:"3.3.8-7etch1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
