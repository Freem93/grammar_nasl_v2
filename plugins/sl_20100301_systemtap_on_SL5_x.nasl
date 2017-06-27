#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

include("compat.inc");

if (description)
{
  script_id(60742);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/14 20:33:26 $");

  script_cve_id("CVE-2009-4273", "CVE-2010-0411");

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
"CVE-2009-4273 systemtap: remote code execution via stap-server

CVE-2010-0411 systemtap: Crash with systemtap script using
__get_argv()

A flaw was found in the SystemTap compile server, stap-server, an
optional component of SystemTap. This server did not adequately
sanitize input provided by the stap-client program, which may allow a
remote user to execute arbitrary shell code with the privileges of the
compile server process, which could possibly be running as the root
user. (CVE-2009-4273)

Note: stap-server is not run by default. It must be started by a user
or administrator.

A buffer overflow flaw was found in SystemTap's tapset __get_argv()
function. If a privileged user ran a SystemTap script that called this
function, a local, unprivileged user could, while that script is still
running, trigger this flaw and cause memory corruption by running a
command with a large argument list, which may lead to a system crash
or, potentially, arbitrary code execution with root privileges.
(CVE-2010-0411)

Note: SystemTap scripts that call __get_argv(), being a privileged
function, can only be executed by the root user or users in the
stapdev group. As well, if such a script was compiled and installed by
root, users in the stapusr group would also be able to execute it."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1003&L=scientific-linux-errata&T=0&P=76
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?33bbb406"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_cwe_id(94, 189);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/03/01");
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
if (rpm_check(release:"SL5", reference:"systemtap-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-client-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-initscript-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-runtime-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-sdt-devel-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-server-0.9.7-5.el5_4.3")) flag++;
if (rpm_check(release:"SL5", reference:"systemtap-testsuite-0.9.7-5.el5_4.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
