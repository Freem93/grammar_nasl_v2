#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1171. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22713);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2014/08/20 15:05:35 $");

  script_cve_id("CVE-2005-3241", "CVE-2005-3242", "CVE-2005-3243", "CVE-2005-3244", "CVE-2005-3246", "CVE-2005-3248", "CVE-2006-4333");
  script_osvdb_id(20121, 20122, 20123, 20124, 20125, 20126, 20127, 20128, 20130, 20131, 20133, 20134, 20135, 28199);
  script_xref(name:"DSA", value:"1171");

  script_name(english:"Debian DSA-1171-1 : ethereal - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several remote vulnerabilities have been discovered in the Ethereal
network scanner, which may lead to the execution of arbitrary code.
The Common Vulnerabilities and Exposures project identifies the
following problems :

  - CVE-2006-4333
    It was discovered that the Q.2391 dissector is
    vulnerable to denial of service caused by memory
    exhaustion.

  - CVE-2005-3241
    It was discovered that the FC-FCS, RSVP and ISIS-LSP
    dissectors are vulnerable to denial of service caused by
    memory exhaustion.

  - CVE-2005-3242
    It was discovered that the IrDA and SMB dissectors are
    vulnerable to denial of service caused by memory
    corruption.

  - CVE-2005-3243
    It was discovered that the SLIMP3 and AgentX dissectors
    are vulnerable to code injection caused by buffer
    overflows.

  - CVE-2005-3244
    It was discovered that the BER dissector is vulnerable
    to denial of service caused by an infinite loop.

  - CVE-2005-3246
    It was discovered that the NCP and RTnet dissectors are
    vulnerable to denial of service caused by a NULL pointer
    dereference.

  - CVE-2005-3248
    It was discovered that the X11 dissector is vulnerable
    to denial of service caused by a division through zero.

This update also fixes a 64 bit-specific regression in the ASN.1
decoder, which was introduced in a previous DSA."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=384528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=334880"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-4333"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3241"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3242"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3243"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3244"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3246"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-3248"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-1171"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the ethereal packages.

For the stable distribution (sarge) these problems have been fixed in
version 0.10.10-2sarge8."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_cwe_id(399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:ethereal");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/09/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/10/19");
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
if (deb_check(release:"3.1", prefix:"ethereal", reference:"0.10.10-2sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-common", reference:"0.10.10-2sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"ethereal-dev", reference:"0.10.10-2sarge8")) flag++;
if (deb_check(release:"3.1", prefix:"tethereal", reference:"0.10.10-2sarge8")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
