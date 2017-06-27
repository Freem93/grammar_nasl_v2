#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60648);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2015/12/01 14:29:29 $");

  script_cve_id("CVE-2009-2692", "CVE-2009-2698");

  script_name(english:"Scientific Linux Security Update : kernel on SL3.x i386/x86_64");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Scientific Linux host is missing one or more security
updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"CVE-2009-2692 kernel: uninit op in SOCKOPS_WRAP() leads to privesc

CVE-2009-2698 kernel: udp socket NULL ptr dereference

These updated packages fix the following security issues :

  - a flaw was found in the SOCKOPS_WRAP macro in the Linux
    kernel. This macro did not initialize the sendpage
    operation in the proto_ops structure correctly. A local,
    unprivileged user could use this flaw to cause a local
    denial of service or escalate their privileges.
    (CVE-2009-2692, Important)

  - a flaw was found in the udp_sendmsg() implementation in
    the Linux kernel when using the MSG_MORE flag on UDP
    sockets. A local, unprivileged user could use this flaw
    to cause a local denial of service or escalate their
    privileges. (CVE-2009-2698, Important)

The system must be rebooted for this update to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0908&L=scientific-linux-errata&T=0&P=2584
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?eff1500b"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/08/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2015 Tenable Network Security, Inc.");
  script_family(english:"Scientific Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/cpu", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Scientific Linux " >!< release) audit(AUDIT_HOST_NOT, "running Scientific Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if (cpu >!< "x86_64" && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Scientific Linux", cpu);


flag = 0;
if (rpm_check(release:"SL3", reference:"kernel-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-BOOT-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-doc-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", cpu:"i386", reference:"kernel-hugemem-unsupported-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-smp-unsupported-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-source-2.4.21-60.EL")) flag++;
if (rpm_check(release:"SL3", reference:"kernel-unsupported-2.4.21-60.EL")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
