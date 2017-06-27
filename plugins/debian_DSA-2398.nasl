#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2398. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57738);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-3389", "CVE-2012-0036");
  script_bugtraq_id(49388, 49778, 51665);
  script_xref(name:"DSA", value:"2398");

  script_name(english:"Debian DSA-2398-2 : curl - several vulnerabilities (BEAST)");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in cURL, an URL transfer
library. The Common Vulnerabilities and Exposures project identifies
the following problems :

  - CVE-2011-3389
    This update enables OpenSSL workarounds against the
    'BEAST' attack. Additional information can be found in
    the cURL advisory

  - CVE-2012-0036
    Dan Fandrich discovered that cURL performs insufficient
    sanitising when extracting the file path part of an URL."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=658276"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3389"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://curl.haxx.se/docs/adv_20120124B.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-0036"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/curl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2398"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the curl packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 7.18.2-8lenny6.

For the stable distribution (squeeze), this problem has been fixed in
version 7.21.0-2.1+squeeze2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:curl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/03/31");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/31");
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
if (deb_check(release:"5.0", prefix:"curl", reference:"7.18.2-8lenny6")) flag++;
if (deb_check(release:"6.0", prefix:"curl", reference:"7.21.0-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3", reference:"7.21.0-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3-dbg", reference:"7.21.0-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl3-gnutls", reference:"7.21.0-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl4-gnutls-dev", reference:"7.21.0-2.1+squeeze2")) flag++;
if (deb_check(release:"6.0", prefix:"libcurl4-openssl-dev", reference:"7.21.0-2.1+squeeze2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
