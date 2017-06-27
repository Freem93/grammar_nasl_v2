#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(65089);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2014/08/16 19:47:28 $");

  script_cve_id("CVE-2013-0809", "CVE-2013-1493");

  script_name(english:"Scientific Linux Security Update : java-1.7.0-openjdk on SL6.x i386/x86_64");
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
"An integer overflow flaw was found in the way the 2D component handled
certain sample model instances. A specially crafted sample model
instance could cause Java Virtual Machine memory corruption and,
possibly, lead to arbitrary code execution with virtual machine
privileges. (CVE-2013-0809)

It was discovered that the 2D component did not properly reject
certain malformed images. Specially crafted raster parameters could
cause Java Virtual Machine memory corruption and, possibly, lead to
arbitrary code execution with virtual machine privileges.
(CVE-2013-1493)

Note: If the web browser plug-in provided by the icedtea-web package
was installed, the issues exposed via Java applets could have been
exploited without user interaction if a user visited a malicious
website.

This erratum also upgrades the OpenJDK package to IcedTea7 2.3.8.

All running instances of OpenJDK Java must be restarted for the update
to take effect."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1303&L=scientific-linux-errata&T=0&P=2570
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?86753005"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java CMM Remote Code Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/06");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/08");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2014 Tenable Network Security, Inc.");
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
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-1.7.0.9-2.3.8.0.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-debuginfo-1.7.0.9-2.3.8.0.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-demo-1.7.0.9-2.3.8.0.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-devel-1.7.0.9-2.3.8.0.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-javadoc-1.7.0.9-2.3.8.0.el6_4")) flag++;
if (rpm_check(release:"SL6", reference:"java-1.7.0-openjdk-src-1.7.0.9-2.3.8.0.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");