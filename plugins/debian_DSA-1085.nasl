#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1085. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22627);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/05/26 15:53:37 $");

  script_cve_id("CVE-2004-1617", "CVE-2005-3120");
  script_bugtraq_id(11443);
  script_osvdb_id(11135, 20019);
  script_xref(name:"DSA", value:"1085");

  script_name(english:"Debian DSA-1085-1 : lynx-cur - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in lynx, the popular
text-mode WWW browser. The Common Vulnerabilities and Exposures
Project identifies the following vulnerabilities :

  - CVE-2004-1617
    Michal Zalewski discovered that lynx is not able to grok
    invalid HTML including a TEXTAREA tag with a large COLS
    value and a large tag name in an element that is not
    terminated, and loops forever trying to render the
    broken HTML.

  - CVE-2005-3120
    Ulf Harnhammar discovered a buffer overflow that can be
    remotely exploited. During the handling of Asian
    characters when connecting to an NNTP server lynx can be
    tricked to write past the boundary of a buffer which can
    lead to the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=296340"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2004-1617"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3120"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1085"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the lynx-cur package.

For the old stable distribution (woody) these problems have been fixed
in version 2.8.5-2.5woody1.

For the stable distribution (sarge) these problems have been fixed in
version 2.8.6-9sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:lynx-cur");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/06/01");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2004/10/18");
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
if (deb_check(release:"3.0", prefix:"lynx-cur", reference:"2.8.5-2.5woody1")) flag++;
if (deb_check(release:"3.0", prefix:"lynx-cur-wrapper", reference:"2.8.5-2.5woody1")) flag++;
if (deb_check(release:"3.1", prefix:"lynx-cur", reference:"2.8.6-9sarge1")) flag++;
if (deb_check(release:"3.1", prefix:"lynx-cur-wrapper", reference:"2.8.6-9sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
