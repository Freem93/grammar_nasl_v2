#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60904);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/01/14 15:20:33 $");

  script_cve_id("CVE-2010-4170", "CVE-2010-4171");

  script_name(english:"Scientific Linux Security Update : systemtap on SL5.x i386/x86_64");
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
"It was discovered that staprun did not properly sanitize the
environment before executing the modprobe command to load an
additional kernel module. A local, unprivileged user could use this
flaw to escalate their privileges. (CVE-2010-4170)

It was discovered that staprun did not check if the module to be
unloaded was previously loaded by SystemTap. A local, unprivileged
user could use this flaw to unload an arbitrary kernel module that was
not in use. (CVE-2010-4171)

Note: After installing this update, users already in the stapdev group
must be added to the stapusr group in order to be able to run the
staprun tool."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1011&L=scientific-linux-errata&T=0&P=1238
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?21fdf41e"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/11/17");
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
if (rpm_check(release:"SL5", reference:"systemtap-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-client-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-initscript-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-runtime-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-sdt-devel-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-server-1.1-3.el5_5.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-testsuite-1.1-3.el5_5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
