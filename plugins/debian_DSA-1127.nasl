#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1127. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22669);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2014/05/03 11:14:57 $");

  script_cve_id("CVE-2006-3628", "CVE-2006-3629", "CVE-2006-3630", "CVE-2006-3631", "CVE-2006-3632");
  script_osvdb_id(27361, 27362, 27363, 27364, 27365, 27366, 27368, 27369, 27370, 27371);
  script_xref(name:"DSA", value:"1127");

  script_name(english:"Debian DSA-1127-1 : ethereal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Ethereal
network sniffer, which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2006-3628
    Ilja van Sprundel discovered that the FW-1 and MQ
    dissectors are vulnerable to format string attacks.

  - CVE-2006-3629
    Ilja van Sprundel discovered that the MOUNT dissector is
    vulnerable to denial of service through memory
    exhaustion.

  - CVE-2006-3630
    Ilja van Sprundel discovered off-by-one overflows in the
    NCP NMAS and NDPS dissectors.

  - CVE-2006-3631
    Ilja van Sprundel discovered a buffer overflow in the
    NFS dissector.

  - CVE-2006-3632
    Ilja van Sprundel discovered that the SSH dissector is
    vulnerable to denial of service through an infinite
    loop."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=373913"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=375694"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3628"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3629"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3630"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3631"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-3632"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1127"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal packages.

For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge6."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/07/28");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2006/07/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"ethereal", reference:"0.10.10-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-common", reference:"0.10.10-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-dev", reference:"0.10.10-2sarge6")) flag++;
if (deb_check(release:"3.1", prefix:"tethereal", reference:"0.10.10-2sarge6")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
