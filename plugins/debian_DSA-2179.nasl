#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2179. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(52513);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2014/08/12 14:36:12 $");

  script_cve_id("CVE-2011-0434", "CVE-2011-0435", "CVE-2011-0436", "CVE-2011-0437");
  script_osvdb_id(72802, 72803, 72804, 72805, 72806, 72807);
  script_xref(name:"DSA", value:"2179");

  script_name(english:"Debian DSA-2179-1 : dtc - SQL injection");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Ansgar Burchardt discovered several vulnerabilities in DTC, a web
control panel for admin and accounting hosting services.

  - CVE-2011-0434
    The bw_per_moth.php graph contains a SQL injection
    vulnerability.

  - CVE-2011-0435
    Insufficient checks in bw_per_month.php can lead to
    bandwidth usage information disclosure.

  - CVE-2011-0436
    After a registration, passwords are sent in cleartext
    email messages.

  - CVE-2011-0437
    Authenticated users could delete accounts using an
    obsolete interface which was incorrectly included in the
    package.

This update introduces a new configuration option which controls the
presence of cleartext passwords in email messages. The default is not
to include cleartext passwords."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=614302"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0434"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0435"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0436"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-0437"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2179"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the dtc packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 0.29.17-1+lenny1.

The stable distribution (squeeze) and the testing distribution
(wheezy) do not contain any dtc packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:dtc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/03/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/03/03");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"dtc", reference:"0.29.17-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
