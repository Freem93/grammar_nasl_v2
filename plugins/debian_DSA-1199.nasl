#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1199. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22908);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/05 14:49:55 $");

  script_cve_id("CVE-2005-3912", "CVE-2006-3392", "CVE-2006-4542");
  script_bugtraq_id(15629, 18744, 19820);
  script_osvdb_id(21222, 26772, 28337, 28338);
  script_xref(name:"DSA", value:"1199");

  script_name(english:"Debian DSA-1199-1 : webmin - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in webmin, a web-based
administration toolkit. The Common Vulnerabilities and Exposures
project identifies the following vulnerabilities :

  - CVE-2005-3912
    A format string vulnerability in miniserv.pl could allow
    an attacker to cause a denial of service by crashing the
    application or exhausting system resources, and could
    potentially allow arbitrary code execution.

  - CVE-2006-3392
    Improper input sanitization in miniserv.pl could allow
    an attacker to read arbitrary files on the webmin host
    by providing a specially crafted URL path to the
    miniserv http server.

  - CVE-2006-4542
    Improper handling of null characters in URLs in
    miniserv.pl could allow an attacker to conduct
    cross-site scripting attacks, read CGI program source
    code, list local directories, and potentially execute
    arbitrary code.

Stable updates are available for alpha, amd64, arm, hppa, i386, ia64,
m68k, mips, mipsel, powerpc, s390 and sparc."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=341394"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=381537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=391284"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3912"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3392"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4542"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1199"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the webmin (1.180-3sarge1) package.

For the stable distribution (sarge), these problems have been fixed in
version 1.180-3sarge1.

Webmin is not included in unstable (sid) or testing (etch), so these
problems are not present."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:webmin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/10/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/25");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/11/29");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"webmin", reference:"1.180-3sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"webmin-core", reference:"1.180-3sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
