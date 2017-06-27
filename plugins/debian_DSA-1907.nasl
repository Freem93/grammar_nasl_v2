#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1907. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44772);
  script_version("$Revision: 1.7 $");
  script_cvs_date("$Date: 2014/05/03 11:20:10 $");

  script_cve_id("CVE-2008-5714", "CVE-2009-3290");
  script_xref(name:"DSA", value:"1907");

  script_name(english:"Debian DSA-1907-1 : kvm - several vulnerabilities");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several vulnerabilities have been discovered in kvm, a full
virtualization system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2008-5714
    Chris Webb discovered an off-by-one bug limiting KVM's
    VNC passwords to 7 characters. This flaw might make it
    easier for remote attackers to guess the VNC password,
    which is limited to seven characters where eight was
    intended.

  - CVE-2009-3290
    It was discovered that the kvm_emulate_hypercall
    function in KVM does not prevent access to MMU
    hypercalls from ring 0, which allows local guest OS
    users to cause a denial of service (guest kernel crash)
    and read or write guest kernel memory.

The oldstable distribution (etch) does not contain kvm."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=509997"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=548975"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2008-5714"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3290"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1907"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kvm packages.

For the stable distribution (lenny), these problems have been fixed in
version 72+dfsg-5~lenny3."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N");
  script_cwe_id(189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2014 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"kvm", reference:"72+dfsg-5~lenny3")) flag++;
if (deb_check(release:"5.0", prefix:"kvm-source", reference:"72+dfsg-5~lenny3")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
