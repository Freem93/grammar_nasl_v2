#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-967. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(22833);
  script_version("$Revision: 1.16 $");
  script_cvs_date("$Date: 2016/09/08 13:32:53 $");

  script_cve_id("CVE-2005-4439", "CVE-2006-0347", "CVE-2006-0348", "CVE-2006-0597", "CVE-2006-0598", "CVE-2006-0599", "CVE-2006-0600");
  script_osvdb_id(21844, 22646, 22647, 22651, 23162, 23163, 23164, 23165);
  script_xref(name:"DSA", value:"967");

  script_name(english:"Debian DSA-967-1 : elog - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security problems have been found in elog, an electronic
logbook to manage notes. The Common Vulnerabilities and Exposures
Project identifies the following problems :

  - CVE-2005-4439
    'GroundZero Security' discovered that elog
    insufficiently checks the size of a buffer used for
    processing URL parameters, which might lead to the
    execution of arbitrary code.

  - CVE-2006-0347
    It was discovered that elog contains a directory
    traversal vulnerability in the processing of '../'
    sequences in URLs, which might lead to information
    disclosure.

  - CVE-2006-0348
    The code to write the log file contained a format string
    vulnerability, which might lead to the execution of
    arbitrary code.

  - CVE-2006-0597
    Overly long revision attributes might trigger a crash
    due to a buffer overflow.

  - CVE-2006-0598
    The code to write the log file does not enforce bounds
    checks properly, which might lead to the execution of
    arbitrary code.

  - CVE-2006-0599
    elog emitted different errors messages for invalid
    passwords and invalid users, which allows an attacker to
    probe for valid user names.

  - CVE-2006-0600
    An attacker could be driven into infinite redirection
    with a crafted 'fail' request, which has denial of
    service potential."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=349528"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2005-4439"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0347"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0348"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0597"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0598"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0599"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2006-0600"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2006/dsa-967"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the elog package.

The old stable distribution (woody) does not contain elog packages.

For the stable distribution (sarge) these problems have been fixed in
version 2.5.7+r1558-4+sarge2."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:elog");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:3.1");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/02/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2006/10/14");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/04/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2006-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"3.1", prefix:"elog", reference:"2.5.7+r1558-4+sarge2")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
