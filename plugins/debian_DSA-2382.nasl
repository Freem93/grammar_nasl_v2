#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2382. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(57522);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/02/16 15:31:56 $");

  script_cve_id("CVE-2011-1831", "CVE-2011-1832", "CVE-2011-1834", "CVE-2011-1835", "CVE-2011-1837", "CVE-2011-3145");
  script_bugtraq_id(49108, 49287);
  script_osvdb_id(74869, 74874, 74875, 74876, 74877, 74878);
  script_xref(name:"DSA", value:"2382");

  script_name(english:"Debian DSA-2382-1 : ecryptfs-utils - multiple vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several problems have been discovered in eCryptfs, a cryptographic
filesystem for Linux.

  - CVE-2011-1831
    Vasiliy Kulikov of Openwall and Dan Rosenberg discovered
    that eCryptfs incorrectly validated permissions on the
    requested mountpoint. A local attacker could use this
    flaw to mount to arbitrary locations, leading to
    privilege escalation.

  - CVE-2011-1832
    Vasiliy Kulikov of Openwall and Dan Rosenberg discovered
    that eCryptfs incorrectly validated permissions on the
    requested mountpoint. A local attacker could use this
    flaw to unmount to arbitrary locations, leading to a
    denial of service.

  - CVE-2011-1834
    Dan Rosenberg and Marc Deslauriers discovered that
    eCryptfs incorrectly handled modifications to the mtab
    file when an error occurs. A local attacker could use
    this flaw to corrupt the mtab file, and possibly unmount
    arbitrary locations, leading to a denial of service.

  - CVE-2011-1835
    Marc Deslauriers discovered that eCryptfs incorrectly
    handled keys when setting up an encrypted private
    directory. A local attacker could use this flaw to
    manipulate keys during creation of a new user.

  - CVE-2011-1837
    Vasiliy Kulikov of Openwall discovered that eCryptfs
    incorrectly handled lock counters. A local attacker
    could use this flaw to possibly overwrite arbitrary
    files.

We acknowledge the work of the Ubuntu distribution in preparing
patches suitable for near-direct inclusion in the Debian package."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1831"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1832"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1834"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1835"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2011-1837"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/squeeze/ecryptfs-utils"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2012/dsa-2382"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ecryptfs-utils packages.

For the oldstable distribution (lenny), these problems have been fixed
in version 68-1+lenny1.

For the stable distribution (squeeze), these problems have been fixed
in version 83-4+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ecryptfs-utils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:6.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/01/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/01/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"ecryptfs-utils", reference:"68-1+lenny1")) flag++;
if (deb_check(release:"6.0", prefix:"ecryptfs-utils", reference:"83-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"ecryptfs-utils-dbg", reference:"83-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecryptfs-dev", reference:"83-4+squeeze1")) flag++;
if (deb_check(release:"6.0", prefix:"libecryptfs0", reference:"83-4+squeeze1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
