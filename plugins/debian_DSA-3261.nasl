#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-3261. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(83501);
  script_version("$Revision: 2.2 $");
  script_cvs_date("$Date: 2015/05/21 17:15:51 $");

  script_cve_id("CVE-2015-3406", "CVE-2015-3407", "CVE-2015-3408", "CVE-2015-3409");
  script_bugtraq_id(73935, 73937);
  script_xref(name:"DSA", value:"3261");

  script_name(english:"Debian DSA-3261-1 : libmodule-signature-perl - security update");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities were discovered in libmodule-signature-perl,
a Perl module to manipulate CPAN SIGNATURE files. The Common
Vulnerabilities and Exposures project identifies the following
problems :

  - CVE-2015-3406
    John Lightsey discovered that Module::Signature could
    parse the unsigned portion of the SIGNATURE file as the
    signed portion due to incorrect handling of PGP
    signature boundaries.

  - CVE-2015-3407
    John Lightsey discovered that Module::Signature
    incorrectly handles files that are not listed in the
    SIGNATURE file. This includes some files in the t/
    directory that would execute when tests are run.

  - CVE-2015-3408
    John Lightsey discovered that Module::Signature uses two
    argument open() calls to read the files when generating
    checksums from the signed manifest. This allows to embed
    arbitrary shell commands into the SIGNATURE file that
    would execute during the signature verification process.

  - CVE-2015-3409
    John Lightsey discovered that Module::Signature
    incorrectly handles module loading, allowing to load
    modules from relative paths in @INC. A remote attacker
    providing a malicious module could use this issue to
    execute arbitrary code during signature verification.

Note that libtest-signature-perl received an update for compatibility
with the fix for CVE-2015-3407 in libmodule-signature-perl."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=783451"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3406"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3408"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3409"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2015-3407"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/wheezy/libmodule-signature-perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://packages.debian.org/source/jessie/libmodule-signature-perl"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2015/dsa-3261"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the libmodule-signature-perl packages.

For the oldstable distribution (wheezy), these problems have been
fixed in version 0.68-1+deb7u2.

For the stable distribution (jessie), these problems have been fixed
in version 0.73-1+deb8u1."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:libmodule-signature-perl");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:7.0");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:8.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/05/15");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/05/18");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (deb_check(release:"7.0", prefix:"libmodule-signature-perl", reference:"0.68-1+deb7u2")) flag++;
if (deb_check(release:"8.0", prefix:"libmodule-signature-perl", reference:"0.73-1+deb8u1")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
