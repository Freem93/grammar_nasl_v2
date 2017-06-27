#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Debian Security Advisory DSA-1962. The text 
# itself is copyright (C) Software in the Public Interest, Inc.
#

include("compat.inc");

if (description)
{
  script_id(44827);
  script_version("$Revision: 1.8 $");
  script_cvs_date("$Date: 2016/12/06 20:25:07 $");

  script_cve_id("CVE-2009-3638", "CVE-2009-3722", "CVE-2009-4031");
  script_xref(name:"DSA", value:"1962");

  script_name(english:"Debian DSA-1962-1 : kvm - several vulnerabilities");
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

  - CVE-2009-3638
    It was discovered an Integer overflow in the
    kvm_dev_ioctl_get_supported_cpuid function. This allows
    local users to have an unspecified impact via a
    KVM_GET_SUPPORTED_CPUID request to the
    kvm_arch_dev_ioctl function.

  - CVE-2009-3722
    It was discovered that the handle_dr function in the KVM
    subsystem does not properly verify the Current Privilege
    Level (CPL) before accessing a debug register, which
    allows guest OS users to cause a denial of service
    (trap) on the host OS via a crafted application.

  - CVE-2009-4031
    It was discovered that the do_insn_fetch function in the
    x86 emulator in the KVM subsystem tries to interpret
    instructions that contain too many bytes to be valid,
    which allows guest OS users to cause a denial of service
    (increased scheduling latency) on the host OS via
    unspecified manipulations related to SMP support."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=557739"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=562075"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://bugs.debian.org/cgi-bin/bugreport.cgi?bug=562076"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3638"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-3722"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security-tracker.debian.org/tracker/CVE-2009-4031"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.debian.org/security/2009/dsa-1962"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"Upgrade the kvm package.

For the stable distribution (lenny), these problems have been fixed in
version 72+dfsg-5~lenny4."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C");
  script_cwe_id(20, 189, 264);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:debian:debian_linux:kvm");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:debian:debian_linux:5.0");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/12/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/02/24");
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
if (deb_check(release:"5.0", prefix:"kvm", reference:"72+dfsg-5~lenny4")) flag++;
if (deb_check(release:"5.0", prefix:"kvm-source", reference:"72+dfsg-5~lenny4")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:deb_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
