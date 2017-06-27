#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-944. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22810);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2014/05/03 11:30:24 $");

  script_cve_id("CVE-2005-4238", "CVE-2005-4518", "CVE-2005-4519", "CVE-2005-4520", "CVE-2005-4521", "CVE-2005-4522", "CVE-2005-4523", "CVE-2005-4524");
  script_bugtraq_id(15842, 16046);
  script_osvdb_id(21686, 22051, 22052, 22053, 22054, 22056, 22057, 22341, 22343);
  script_xref(name:"DSA", value:"944");

  script_name(english:"Debian DSA-944-1 : mantis - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in Mantis, a
web-based bug tracking system. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2005-4238
    Missing input sanitising allows remote attackers to
    inject arbitrary web script or HTML.

  - CVE-2005-4518
    Tobias Klein discovered that Mantis allows remote
    attackers to bypass the file upload size restriction.

  - CVE-2005-4519
    Tobias Klein discovered several SQL injection
    vulnerabilities that allow remote attackers to execute
    arbitrary SQL commands.

  - CVE-2005-4520
    Tobias Klein discovered unspecified 'port injection'
    vulnerabilities in filters.

  - CVE-2005-4521
    Tobias Klein discovered a CRLF injection vulnerability
    that allows remote attackers to modify HTTP headers and
    conduct HTTP response splitting attacks.

  - CVE-2005-4522
    Tobias Klein discovered several cross-site scripting
    (XSS) vulnerabilities that allow remote attackers to
    inject arbitrary web script or HTML.

  - CVE-2005-4523
    Tobias Klein discovered that Mantis discloses private
    bugs via public RSS feeds, which allows remote attackers
    to obtain sensitive information.

  - CVE-2005-4524
    Tobias Klein discovered that Mantis does not properly
    handle 'Make note private' when a bug is being resolved,
    which has unknown impact and attack vectors, probably
    related to an information leak.

The old stable distribution (woody) does not seem to be affected by
these problems."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=345288"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4238"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4518"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4519"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4520"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4521"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4522"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4523"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4524"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-944"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mantis package.

For the stable distribution (sarge) these problems have been fixed in
version 0.19.2-5sarge1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:H/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No exploit is required");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mantis");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/01/17");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/12/13");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"mantis", reference:"0.19.2-5sarge1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
