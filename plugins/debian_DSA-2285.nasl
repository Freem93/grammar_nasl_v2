#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2285. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55694);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:41 $");

  script_cve_id("CVE-2011-2703", "CVE-2011-2704");
  script_bugtraq_id(48720);
  script_osvdb_id(74040, 74041, 74042);
  script_xref(name:"DSA", value:"2285");

  script_name(english:"Debian DSA-2285-1 : mapserver - several vulnerabilities");
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

  - CVE-2011-2703
    Several instances of insufficient escaping of user
    input, leading to SQL injection attacks via OGC filter
    encoding (in WMS, WFS, and SOS filters).

  - CVE-2011-2704
    Missing length checks in the processing of OGC filter
    encoding that can lead to stack-based buffer overflows
    and the execution of arbitrary code."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2703"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-2704"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/mapserver"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2285"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the mapserver packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 5.0.3-3+lenny7.

For the stable distribution (squeeze), these problems have been fixed
in version 5.6.5-2+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:mapserver");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/07/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/07/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"mapserver", reference:"5.0.3-3+lenny7")) flag++;
if (deb_check(release:"6.0", prefix:"cgi-mapserver", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libmapscript-ruby", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libmapscript-ruby1.8", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libmapscript-ruby1.9.1", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mapserver-bin", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"mapserver-doc", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"perl-mapscript", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"php5-mapscript", reference:"5.6.5-2+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"python-mapscript", reference:"5.6.5-2+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
