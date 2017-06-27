#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60358);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2008-0600");

  script_name(english:"Scientific Linux Security Update : kernel on SL5.x i386/x86_64");
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
"A flaw was found in vmsplice. An unprivileged local user could use
this flaw to gain root privileges. (CVE-2008-0600)

There is a public available exploit for this issue."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind0802&L=scientific-linux-errata&T=0&P=689
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?edc58a84"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(94);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2008/02/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2012/08/01");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL5", reference:"kernel-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-PAE-devel-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-debug-devel-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-devel-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-doc-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-headers-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-fuse-2.6.18-53.1.13.el5-2.6.3-1.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-fuse-2.6.18-53.1.13.el5PAE-2.6.3-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-fuse-2.6.18-53.1.13.el5xen-2.6.3-1.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-53.1.13.el5-1.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ipw3945-2.6.18-53.1.13.el5PAE-1.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ipw3945-2.6.18-53.1.13.el5xen-1.2.0-2.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-53.1.13.el5-0.9.3.3-12.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-2.6.18-53.1.13.el5PAE-0.9.3.3-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-2.6.18-53.1.13.el5xen-0.9.3.3-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-53.1.13.el5-0.9.3.3-12.el5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-madwifi-hal-2.6.18-53.1.13.el5PAE-0.9.3.3-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-madwifi-hal-2.6.18-53.1.13.el5xen-0.9.3.3-12.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-53.1.13.el5-1.41-1.SL")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-ndiswrapper-2.6.18-53.1.13.el5PAE-1.41-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-ndiswrapper-2.6.18-53.1.13.el5xen-1.41-1.SL")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.13.el5-1.4.6-58.SL5")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-openafs-2.6.18-53.1.13.el5PAE-1.4.6-58.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-openafs-2.6.18-53.1.13.el5xen-1.4.6-58.SL5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-r1000-2.6.18-53.1.13.el5-1.05-1.sl")) flag++;
if (rpm_check(release:"SL5", cpu:"i386", reference:"kernel-module-r1000-2.6.18-53.1.13.el5PAE-1.05-1.sl")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-module-r1000-2.6.18-53.1.13.el5xen-1.05-1.sl")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-2.6.18-53.1.13.el5")) flag++;
if (rpm_check(release:"SL5", reference:"kernel-xen-devel-2.6.18-53.1.13.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
