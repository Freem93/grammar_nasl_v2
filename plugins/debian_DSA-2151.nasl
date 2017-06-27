#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2151. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(51677);
  script_version("$Revision: 1.15 $");
  script_cvs_date("$Date: 2016/05/16 13:53:25 $");

  script_cve_id("CVE-2010-3450", "CVE-2010-3451", "CVE-2010-3452", "CVE-2010-3453", "CVE-2010-3454", "CVE-2010-3689", "CVE-2010-4253", "CVE-2010-4643");
  script_osvdb_id(70711, 70712, 70713, 70714, 70715, 70716, 70717, 70718);
  script_xref(name:"DSA", value:"2151");

  script_name(english:"Debian DSA-2151-1 : openoffice.org - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several security related problems have been discovered in the
OpenOffice.org package that allows malformed documents to trick the
system into crashes or even the execution of arbitrary code.

  - CVE-2010-3450
    During an internal security audit within Red Hat, a
    directory traversal vulnerability has been discovered in
    the way OpenOffice.org 3.1.1 through 3.2.1 processes XML
    filter files. If a local user is tricked into opening a
    specially crafted OOo XML filters package file, this
    problem could allow remote attackers to create or
    overwrite arbitrary files belonging to local user or,
    potentially, execute arbitrary code.

  - CVE-2010-3451
    During his work as a consultant at Virtual Security
    Research (VSR), Dan Rosenberg discovered a vulnerability
    in OpenOffice.org's RTF parsing functionality. Opening a
    maliciously crafted RTF document can cause an
    out-of-bounds memory read into previously allocated heap
    memory, which may lead to the execution of arbitrary
    code.

  - CVE-2010-3452
    Dan Rosenberg discovered a vulnerability in the RTF file
    parser which can be leveraged by attackers to achieve
    arbitrary code execution by convincing a victim to open
    a maliciously crafted RTF file.

  - CVE-2010-3453
    As part of his work with Virtual Security Research, Dan
    Rosenberg discovered a vulnerability in the
    WW8ListManager::WW8ListManager() function of
    OpenOffice.org that allows a maliciously crafted file to
    cause the execution of arbitrary code.

  - CVE-2010-3454
    As part of his work with Virtual Security Research, Dan
    Rosenberg discovered a vulnerability in the
    WW8DopTypography::ReadFromMem() function in
    OpenOffice.org that may be exploited by a maliciously
    crafted file which allows an attacker to control program
    flow and potentially execute arbitrary code.

  - CVE-2010-3689
    Dmitri Gribenko discovered that the soffice script does
    not treat an empty LD_LIBRARY_PATH variable like an
    unset one, which may lead to the execution of arbitrary
    code.

  - CVE-2010-4253
    A heap based buffer overflow has been discovered with
    unknown impact.

  - CVE-2010-4643
    A vulnerability has been discovered in the way
    OpenOffice.org handles TGA graphics which can be tricked
    by a specially crafted TGA file that could cause the
    program to crash due to a heap-based buffer overflow
    with unknown impact."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3450"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3452"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3453"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3454"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-3689"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4253"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-4643"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2011/dsa-2151"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the OpenOffice.org packages.

For the stable distribution (lenny) these problems have been fixed in
version 2.4.1+dfsg-1+lenny11.

For the upcoming stable distribution (squeeze) these problems have
been fixed in version 3.2.1-11+squeeze1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:openoffice.org");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/26");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/01/27");
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
if (deb_check(release:"5.0", prefix:"openoffice.org", reference:"2.4.1+dfsg-1+lenny11")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
