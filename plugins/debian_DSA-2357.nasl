#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2357. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(56999);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2010-2640", "CVE-2010-2641", "CVE-2010-2642", "CVE-2010-2643");
  script_bugtraq_id(45678);
  script_osvdb_id(70300, 70301, 70303);
  script_xref(name:"DSA", value:"2357");

  script_name(english:"Debian DSA-2357-1 : evince - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Jon Larimer from IBM X-Force Advanced Research discovered multiple
vulnerabilities in the DVI backend of the Evince document viewer :

  - CVE-2010-2640
    Insufficient array bounds checks in the PK fonts parser
    could lead to function pointer overwrite, causing
    arbitrary code execution.

  - CVE-2010-2641
    Insufficient array bounds checks in the VF fonts parser
    could lead to function pointer overwrite, causing
    arbitrary code execution.

  - CVE-2010-2642
    Insufficient bounds checks in the AFM fonts parser when
    writing data to a memory buffer allocated on heap could
    lead to arbitrary memory overwrite and arbitrary code
    execution.

  - CVE-2010-2643
    Insufficient check on an integer used as a size for
    memory allocation can lead to arbitrary write outside
    the allocated range and cause arbitrary code execution."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=609534"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2640"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2641"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-2642"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/evince"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2357"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the evince packages.

For the oldstable distribution (lenny), this problem has been fixed in
version 2.22.2-4~lenny2.

For the stable distribution (squeeze), CVE-2010-2640, CVE-2010-2641
and CVE-2010-2643 have been fixed in version 2.30.3-2 but the fix for
CVE-2010-2642 was incomplete. The final fix is present in version
2.30.3-2+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:evince");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/12/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/12/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"evince", reference:"2.22.2-4~lenny2")) flag++;
if (deb_check(release:"6.0", prefix:"evince", reference:"2.30.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"evince-common", reference:"2.30.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"evince-dbg", reference:"2.30.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"evince-gtk", reference:"2.30.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"gir1.0-evince-2.30", reference:"2.30.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"libevince-dev", reference:"2.30.3-2")) flag++;
if (deb_check(release:"6.0", prefix:"libevince2", reference:"2.30.3-2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
