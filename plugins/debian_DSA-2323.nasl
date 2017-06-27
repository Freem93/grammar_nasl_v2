#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2323. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56669);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/05 14:58:42 $");

  script_cve_id("CVE-2011-3602", "CVE-2011-3604", "CVE-2011-3605");
  script_bugtraq_id(50395);
  script_osvdb_id(76128, 76130, 76131);
  script_xref(name:"DSA", value:"2323");

  script_name(english:"Debian DSA-2323-1 : radvd - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple security issues were discovered by Vasiliy Kulikov in radvd,
an IPv6 Router Advertisement daemon :

  - CVE-2011-3602
    set_interface_var() function doesn't check the interface
    name, which is chosen by an unprivileged user. This
    could lead to an arbitrary file overwrite if the
    attacker has local access, or specific files overwrites
    otherwise.

  - CVE-2011-3604
    process_ra() function lacks multiple buffer length
    checks which could lead to memory reads outside the
    stack, causing a crash of the daemon.

  - CVE-2011-3605
    process_rs() function calls mdelay() (a function to wait
    for a defined time) unconditionnally when running in
    unicast-only mode. As this call is in the main thread,
    that means all request processing is delayed (for a time
    up to MAX_RA_DELAY_TIME, 500 ms by default). An attacker
    could flood the daemon with router solicitations in
    order to fill the input queue, causing a temporary
    denial of service (processing would be stopped during
    all the mdelay() calls). Note: upstream and Debian
    default is to use anycast mode."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=644614"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3602"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3604"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-3605"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/radvd"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2323"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the radvd packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 1:1.1-3.1.

For the stable distribution (squeeze), this problem has been fixed in
version 1:1.6-1.1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:radvd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/10/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/10/31");
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
if (deb_check(release:"5.0", prefix:"radvd", reference:"1:1.1-3.1")) flag++;
if (deb_check(release:"6.0", prefix:"radvd", reference:"1:1.6-1.1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
