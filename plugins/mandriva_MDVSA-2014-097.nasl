#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Mandriva Linux Security Advisory MDVSA-2014:097. 
# The text itself is copyright (C) Mandriva S.A.
#

include("compat.inc");

if (description)
{
  script_id(74075);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2014/05/19 13:44:45 $");

  script_cve_id("CVE-2013-6456", "CVE-2014-0179");
  script_bugtraq_id(65743, 67289);
  script_xref(name:"MDVSA", value:"2014:097");

  script_name(english:"Mandriva Linux Security Advisory : libvirt (MDVSA-2014:097)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Mandriva Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Multiple vulnerabilities has been discovered and corrected in 
libvirt :

The LXC driver (lxc/lxc_driver.c) in libvirt 1.0.1 through 1.2.1
allows local users to (1) delete arbitrary host devices via the
virDomainDeviceDettach API and a symlink attack on /dev in the
container; (2) create arbitrary nodes (mknod) via the
virDomainDeviceAttach API and a symlink attack on /dev in the
container; and cause a denial of service (shutdown or reboot host OS)
via the (3) virDomainShutdown or (4) virDomainReboot API and a symlink
attack on /dev/initctl in the container, related to paths under
/proc//root and the virInitctlSetRunLevel function (CVE-2013-6456).

libvirt was patched to prevent expansion of entities when parsing XML
files. This vulnerability allowed malicious users to read arbitrary
files or cause a denial of service (CVE-2014-0179).

The updated packages have been upgraded to the 1.1.3.5 version and
patched to correct these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2014-05/msg00048.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://security.libvirt.org/2014/0003.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:S/C:N/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64virt-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:lib64virt0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:libvirt-utils");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:mandriva:linux:python-libvirt");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:mandriva:business_server:1");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/05/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/05/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");
  script_family(english:"Mandriva Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/Mandrake/release", "Host/Mandrake/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Mandrake/release")) audit(AUDIT_OS_NOT, "Mandriva / Mandake Linux");
if (!get_kb_item("Host/Mandrake/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu !~ "^(amd64|i[3-6]86|x86_64)$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Mandriva / Mandrake Linux", cpu);


flag = 0;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64virt-devel-1.1.3.5-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"lib64virt0-1.1.3.5-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"libvirt-utils-1.1.3.5-1.mbs1")) flag++;
if (rpm_check(release:"MDK-MBS1", cpu:"x86_64", reference:"python-libvirt-1.1.3.5-1.mbs1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
