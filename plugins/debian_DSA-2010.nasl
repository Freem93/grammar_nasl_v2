#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-2010. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(45026);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2010-0298", "CVE-2010-0306", "CVE-2010-0309", "CVE-2010-0419");
  script_xref(name:"DSA", value:"2010");

  script_name(english:"Debian DSA-2010-1 : kvm - privilege escalation/denial of service");
  script_summary(english:"Checks dpkg output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Debian host is missing a security-related update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Several local vulnerabilities have been discovered in kvm, a full
virtualization system. The Common Vulnerabilities and Exposures
project identifies the following problems :

  - CVE-2010-0298 CVE-2010-0306
    Gleb Natapov discovered issues in the KVM subsystem
    where missing permission checks (CPL/IOPL) permit a user
    in a guest system to denial of service a guest (system
    crash) or gain escalated privileges with the guest.

  - CVE-2010-0309
    Marcelo Tosatti fixed an issue in the PIT emulation code
    in the KVM subsystem that allows privileged users in a
    guest domain to cause a denial of service (crash) of the
    host system.

  - CVE-2010-0419
    Paolo Bonzini found a bug in KVM that can be used to
    bypass proper permission checking while loading segment
    selectors. This potentially allows privileged guest
    users to execute privileged instructions on the host
    system."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0298"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0306"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0309"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2010-0419"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2010/dsa-2010"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kvm package.

For the stable distribution (lenny), this problem has been fixed in
version 72+dfsg-5~lenny5."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:C");
  script_cwe_id(16, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2016 Tenable Network Security, Inc.");
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
if (deb_check(release:"5.0", prefix:"kvm", reference:"72+dfsg-5~lenny5")) flag++;
if (deb_check(release:"5.0", prefix:"kvm-source", reference:"72+dfsg-5~lenny5")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:deb_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
