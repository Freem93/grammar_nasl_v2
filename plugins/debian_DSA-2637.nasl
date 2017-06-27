#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2637. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(64995);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2015/02/16 15:37:39 $");

  script_cve_id("CVE-2012-3499", "CVE-2012-4558", "CVE-2013-1048");
  script_bugtraq_id(58165);
  script_osvdb_id(90556, 90557, 90852);
  script_xref(name:"DSA", value:"2637");

  script_name(english:"Debian DSA-2637-1 : apache2 - several issues");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been found in the Apache HTTPD server.

  - CVE-2012-3499
    The modules mod_info, mod_status, mod_imagemap,
    mod_ldap, and mod_proxy_ftp did not properly escape
    hostnames and URIs in HTML output, causing cross site
    scripting vulnerabilities.

  - CVE-2012-4558
    Mod_proxy_balancer did not properly escape hostnames and
    URIs in its balancer-manager interface, causing a cross
    site scripting vulnerability.

  - CVE-2013-1048
    Hayawardh Vijayakumar noticed that the apache2ctl script
    created the lock directory in an unsafe manner, allowing
    a local attacker to gain elevated privileges via a
    symlink attack. This is a Debian specific issue."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-3499"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2012-4558"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2013-1048"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/apache2"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2013/dsa-2637"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the apache2 packages.

For the stable distribution (squeeze), these problems have been fixed
in version 2.2.16-6+squeeze11."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:apache2");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"6.0", prefix:"apache2", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-dbg", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-doc", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-event", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-itk", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-prefork", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-mpm-worker", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-prefork-dev", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-suexec-custom", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-threaded-dev", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2-utils", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-bin", reference:"2.2.16-6+squeeze11")) flag++;
if (deb_check(release:"6.0", prefix:"apache2.2-common", reference:"2.2.16-6+squeeze11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
