#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2079. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(48222);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2010-2539", "CVE-2010-2540");
  script_bugtraq_id(41855);
  script_xref(name:"DSA", value:"2079");

  script_name(english:"Debian DSA-2079-1 : mapserver - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in mapserver, a CGI-based
web framework to publish spatial data and interactive mapping
applications. The Common Vulnerabilities and Exposures project
identifies the following problems :

  - CVE-2010-2539
    A stack-based buffer overflow in the msTmpFile function
    might lead to arbitrary code execution under some
    conditions.

  - CVE-2010-2540
    It was discovered that the CGI debug command-line
    arguments which are enabled by default are insecure and
    may allow a remote attacker to execute arbitrary code.
    Therefore they have been disabled by default."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2539"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2540"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2079"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mapserver packages.

For the stable distribution (lenny), this problem has been fixed in
version 5.0.3-3+lenny5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mapserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/07/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/08/03");
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
if (deb_check(release:"5.0", prefix:"cgi-mapserver", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libmapscript-ruby", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libmapscript-ruby1.8", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"libmapscript-ruby1.9", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"mapserver-bin", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"mapserver-doc", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"perl-mapscript", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"php5-mapscript", reference:"5.0.3-3+lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"python-mapscript", reference:"5.0.3-3+lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
