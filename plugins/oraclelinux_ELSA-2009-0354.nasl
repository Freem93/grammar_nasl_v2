#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Red Hat Security Advisory RHSA-2009:0354 and 
# Oracle Linux Security Advisory ELSA-2009-0354 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67825);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/12/07 20:57:50 $");

  script_cve_id("CVE-2009-0547", "CVE-2009-0582", "CVE-2009-0587");
  script_bugtraq_id(33720, 34100, 34109);
  script_osvdb_id(52673, 52701, 52702, 52703);
  script_xref(name:"RHSA", value:"2009:0354");

  script_name(english:"Oracle Linux 4 / 5 : evolution-data-server (ELSA-2009-0354)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"From Red Hat Security Advisory 2009:0354 :

Updated evolution-data-server and evolution28-evolution-data-server
packages that fix multiple security issues are now available for Red
Hat Enterprise Linux 4 and 5.

This update has been rated as having moderate security impact by the
Red Hat Security Response Team.

Evolution Data Server provides a unified back-end for applications
which interact with contacts, task, and calendar information.
Evolution Data Server was originally developed as a back-end for
Evolution, but is now used by multiple other applications.

Evolution Data Server did not properly check the Secure/Multipurpose
Internet Mail Extensions (S/MIME) signatures used for public key
encryption and signing of e-mail messages. An attacker could use this
flaw to spoof a signature by modifying the text of the e-mail message
displayed to the user. (CVE-2009-0547)

It was discovered that Evolution Data Server did not properly validate
NTLM (NT LAN Manager) authentication challenge packets. A malicious
server using NTLM authentication could cause an application using
Evolution Data Server to disclose portions of its memory or crash
during user authentication. (CVE-2009-0582)

Multiple integer overflow flaws which could cause heap-based buffer
overflows were found in the Base64 encoding routines used by Evolution
Data Server. This could cause an application using Evolution Data
Server to crash, or, possibly, execute an arbitrary code when large
untrusted data blocks were Base64-encoded. (CVE-2009-0587)

All users of evolution-data-server and
evolution28-evolution-data-server are advised to upgrade to these
updated packages, which contain backported patches to correct these
issues. All running instances of Evolution Data Server and
applications using it (such as Evolution) must be restarted for the
update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-March/000915.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2009-March/000917.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected evolution-data-server packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(20, 189, 310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution-data-server-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution28-evolution-data-server");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:evolution28-evolution-data-server-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2009/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || !eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux)", string:release)) audit(AUDIT_OS_NOT, "Oracle Linux");
os_ver = eregmatch(pattern: "Oracle (?:Linux Server|Enterprise Linux) .*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Oracle Linux");
os_ver = os_ver[1];
if (! ereg(pattern:"^(4|5)([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Oracle Linux 4 / 5", "Oracle Linux " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);

flag = 0;
if (rpm_check(release:"EL4", reference:"evolution28-evolution-data-server-1.8.0-37.el4_7.2")) flag++;
if (rpm_check(release:"EL4", reference:"evolution28-evolution-data-server-devel-1.8.0-37.el4_7.2")) flag++;

if (rpm_check(release:"EL5", reference:"evolution-data-server-1.12.3-10.el5_3.3")) flag++;
if (rpm_check(release:"EL5", reference:"evolution-data-server-devel-1.12.3-10.el5_3.3")) flag++;
if (rpm_check(release:"EL5", reference:"evolution-data-server-doc-1.12.3-10.el5_3.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "evolution-data-server / evolution-data-server-devel / etc");
}
