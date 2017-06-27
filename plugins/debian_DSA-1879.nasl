#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1879. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44744);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2015/03/30 13:45:22 $");

  script_cve_id("CVE-2008-7159", "CVE-2008-7160", "CVE-2009-3051", "CVE-2009-3163");
  script_bugtraq_id(36194);
  script_osvdb_id(56761, 57830, 57831, 58033);
  script_xref(name:"DSA", value:"1879");

  script_name(english:"Debian DSA-1879-1 : silc-client/silc-toolkit - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in the software suite for
the SILC protocol, a network protocol designed to provide end-to-end
security for conferencing services. The Common Vulnerabilities and
Exposures project identifies the following problems :

  - CVE-2008-7159
    An incorrect format string in sscanf() used in the ASN1
    encoder to scan an OID value could overwrite a
    neighbouring variable on the stack as the destination
    data type is smaller than the source type on 64-bit. On
    64-bit architectures this could result in unexpected
    application behaviour or even code execution in some
    cases.

  - CVE-2009-3051
    Various format string vulnerabilities when handling
    parsed SILC messages allow an attacker to execute
    arbitrary code with the rights of the victim running the
    SILC client via crafted nick names or channel names
    containing format strings.

  - CVE-2008-7160
    An incorrect format string in a sscanf() call used in
    the HTTP server component of silcd could result in
    overwriting a neighbouring variable on the stack as the
    destination data type is smaller than the source type on
    64-bit. An attacker could exploit this by using crafted
    Content-Length header values resulting in unexpected
    application behaviour or even code execution in some
    cases.

silc-server doesn't need an update as it uses the shared library
provided by silc-toolkit. silc-client/silc-toolkit in the oldstable
distribution (etch) is not affected by this problem."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-7159"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3051"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-7160"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1879"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the silc-toolkit/silc-client packages.

For the stable distribution (lenny), this problem has been fixed in
version 1.1.7-2+lenny1 of silc-toolkit and in version 1.1.4-1+lenny1
of silc-client."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");
  script_cwe_id(134);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:silc-toolkit");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/09/04");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"irssi-plugin-silc", reference:"1.1.4-1+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsilc-1.1-2", reference:"1.1.7-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsilc-1.1-2-dbg", reference:"1.1.7-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"libsilc-1.1-2-dev", reference:"1.1.7-2+lenny1")) flag++;
if (deb_check(release:"5.0", prefix:"silc", reference:"1.1.4-1+lenny1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
