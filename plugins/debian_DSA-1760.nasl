#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1760. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(36053);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2016/12/06 20:12:51 $");

  script_cve_id("CVE-2008-4190", "CVE-2009-0790");
  script_bugtraq_id(31243, 34296);
  script_osvdb_id(53208, 53209);
  script_xref(name:"DSA", value:"1760");

  script_name(english:"Debian DSA-1760-1 : openswan - denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Two vulnerabilities have been discovered in openswan, an IPSec
implementation for linux. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-4190
    Dmitry E. Oboukhov discovered that the livetest tool is
    using temporary files insecurely, which could lead to a
    denial of service attack.

  - CVE-2009-0790
    Gerd v. Egidy discovered that the Pluto IKE daemon in
    openswan is prone to a denial of service attack via a
    malicious packet."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=496374"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-4190"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-0790"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1760"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the openswan packages.

For the oldstable distribution (etch), this problem has been fixed in
version 2.4.6+dfsg.2-1.1+etch1.

For the stable distribution (lenny), this problem has been fixed in
version 2.4.12+dfsg-1.3+lenny1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(20, 59);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openswan");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:4.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2009/03/31");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2009-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"4.0", prefix:"linux-patch-openswan", reference:"2.4.6+dfsg.2-1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openswan", reference:"2.4.6+dfsg.2-1.1+etch1")) flag++;
if (deb_check(release:"4.0", prefix:"openswan-modules-source", reference:"2.4.6+dfsg.2-1.1+etch1")) flag++;
if (deb_check(release:"5.0", prefix:"linux-patch-openswan", reference:"2.4.12+dfsg-1.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openswan", reference:"2.4.12+dfsg-1.3+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"openswan-modules-source", reference:"2.4.12+dfsg-1.3+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
