#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2365. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57505);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/12 14:36:12 $");

  script_cve_id("CVE-2011-3195", "CVE-2011-3196", "CVE-2011-3197", "CVE-2011-3198", "CVE-2011-3199");
  script_bugtraq_id(49267);
  script_osvdb_id(74857, 74858, 74860, 104879, 104880);
  script_xref(name:"DSA", value:"2365");

  script_name(english:"Debian DSA-2365-1 : dtc - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ansgar Burchardt, Mike O'Connor and Philipp Kern discovered multiple
vulnerabilities in DTC, a web control panel for admin and accounting
hosting services :

  - CVE-2011-3195
    A possible shell insertion has been found in the mailing
    list handling.

  - CVE-2011-3196
    Unix rights for the apache2.conf were set incorrectly
    (world readable).

  - CVE-2011-3197
    Incorrect input sanitising for the $_SERVER['addrlink']
    parameter could lead to SQL insertion.

  - CVE-2011-3198
    DTC was using the -b option of htpasswd, possibly
    revealing password in clear text using ps or reading
    /proc.

  - CVE-2011-3199
    A possible HTML/JavaScript insertion vulnerability has
    been found in the DNS & MX section of the user panel.

This update also fixes several vulnerabilities, for which no CVE ID
has been assigned :

It has been discovered that DTC performs insufficient input sanitising
in the package installer, leading to possible unwanted destination
directory for installed packages if some DTC application packages are
installed (note that these aren't available in Debian main).

DTC was setting-up /etc/sudoers with permissive sudo rights to
chrootuid.

Incorrect input sanitizing in the package installer could lead to SQL
insertion.

A malicious user could enter a specially crafted support ticket
subject leading to a SQL injection in the draw_user_admin.php."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637469"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637477"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637485"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637584"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637618"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637537"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637487"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=637669"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3195"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3196"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3197"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3198"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3199"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2365"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dtc packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.29.18-1+lenny2.

The stable distribution (squeeze) doesn't include dtc."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dtc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/18");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"dtc", reference:"0.29.18-1+lenny2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
