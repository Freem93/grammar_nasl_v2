#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2028. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45427);
  script_version("$Revision: 1.11 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-1188", "CVE-2009-3603", "CVE-2009-3604", "CVE-2009-3606", "CVE-2009-3608", "CVE-2009-3609");
  script_bugtraq_id(34568, 36703);
  script_osvdb_id(54808, 59175, 59176, 59177, 59178, 59179, 59180, 59181, 59182, 59183);
  script_xref(name:"DSA", value:"2028");

  script_name(english:"Debian DSA-2028-1 : xpdf - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been identified in xpdf, a suite of tools
for viewing and converting Portable Document Format (PDF) files.

The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2009-1188 and CVE-2009-3603
    Integer overflow in SplashBitmap::SplashBitmap which
    might allow remote attackers to execute arbitrary code
    or an application crash via a crafted PDF document.

  - CVE-2009-3604
    NULL pointer dereference or heap-based buffer overflow
    in Splash::drawImage which might allow remote attackers
    to cause a denial of service (application crash) or
    possibly execute arbitrary code via a crafted PDF
    document.

  - CVE-2009-3606
    Integer overflow in the PSOutputDev::doImageL1Sep which
    might allow remote attackers to execute arbitrary code
    via a crafted PDF document.

  - CVE-2009-3608
    Integer overflow in the ObjectStream::ObjectStream which
    might allow remote attackers to execute arbitrary code
    via a crafted PDF document.

  - CVE-2009-3609
    Integer overflow in the ImageStream::ImageStream which
    might allow remote attackers to cause a denial of
    service via a crafted PDF document."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=551287"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-1188"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3603"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3606"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3608"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3609"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2028"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"For the stable distribution (lenny), this problem has been fixed in
version 3.02-1.4+lenny2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(189, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:xpdf");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/04/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/04/06");
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
if (deb_check(release:"5.0", prefix:"xpdf", reference:"3.02-1.4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf-common", reference:"3.02-1.4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf-reader", reference:"3.02-1.4+lenny2")) flag++;
if (deb_check(release:"5.0", prefix:"xpdf-utils", reference:"3.02-1.4+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
