#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1792. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(38702);
  script_version("$Revision: 1.12 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2009-1575", "CVE-2009-1576");
  script_bugtraq_id(34779);
  script_xref(name:"DSA", value:"1792");

  script_name(english:"Debian DSA-1792-1 : drupal6 - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities have been discovered in drupal, a web content
management system. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2009-1575
    pod.Edge discovered a cross-site scripting vulnerability
    due that can be triggered when some browsers interpret
    UTF-8 strings as UTF-7 if they appear before the
    generated HTML document defines its Content-Type. This
    allows a malicious user to execute arbitrary JavaScript
    in the context of the website if they're allowed to post
    content.

  - CVE-2009-1576
    Moritz Naumann discovered an information disclosure
    vulnerability. If a user is tricked into visiting the
    site via a specially crafted URL and then submits a form
    (such as the search box) from that page, the information
    in their form submission may be directed to a
    third-party site determined by the URL and thus
    disclosed to the third-party. The third-party site may
    then execute a cross-site request forgery attack against
    the submitted form."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=526378"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1575"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1576"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1792"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the drupal6 package.

The old stable distribution (etch) does not contain drupal and is not
affected.

For the stable distribution (lenny), these problems have been fixed in
version 6.6-3lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(79);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:drupal6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/05/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/05/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"drupal6", reference:"6.6-3lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
