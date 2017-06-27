#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0628. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(79277);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2017/01/04 15:51:48 $");

  script_cve_id("CVE-2010-2811");
  script_bugtraq_id(42580);
  script_osvdb_id(67469);
  script_xref(name:"RHSA", value:"2010:0628");

  script_name(english:"RHEL 5 : vdsm22 (RHSA-2010:0628)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated vdsm22 packages that fix one security issue and multiple bugs
are now available for Red Hat Enterprise Linux 5.5.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

VDSM is a management module that serves as a Red Hat Enterprise
Virtualization Manager agent on Red Hat Enterprise Virtualization
Hypervisor or Red Hat Enterprise Linux hosts.

Note: This update has been tested and is supported on Red Hat
Enterprise Linux 5.5 (with all appropriate post-GA 5.5-specific
updates).

A flaw was found in the way VDSM accepted SSL connections. An attacker
could trigger this flaw by creating a crafted SSL connection to VDSM,
preventing VDSM from accepting SSL connections from other users.
(CVE-2010-2811)

These updated vdsm22 packages also fix the following bugs :

* suspend-to-file hibernation failed for huge guests due to the
migration and hibernation constant values being too short for huge
guests. This update makes the timeouts proportional to guest RAM size,
thus allowing suspension of huge guests in all cases except where
storage is unbearably slow. (BZ#601275)

* under certain circumstances, restarting a VDSM that was being used
as a Storage Pool Manager killed all system processes on the host.
With this update, stopping VDSM is ensured to kill only the processes
that it started, and the VDSM SIGTERM handler is not run concurrently.
With these changes, all processes on the host are no longer killed
when VDSM is restarted. (BZ#614849)

* when VDSM was requested to 'start in paused mode', it incorrectly
reported virtual guest state as 'WaitForLaunch' instead of 'Paused',
which led to the virtual guest being inaccessible from Red Hat
Enterprise Virtualization Manager. With this update, VDSM reports such
virtual guests as 'Paused', and users are able to connect to the
virtual guest display. (BZ#616464)

Red Hat Enterprise Virtualization Manager 2.2 users with Red Hat
Enterprise Linux hosts should install these updated packages, which
resolve these issues. Alternatively, Red Hat Enterprise Virtualization
Manager can install the new package automatically."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2010-2811.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2010-0628.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vdsm22 and / or vdsm22-cli packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:A/AC:M/Au:N/C:N/I:N/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm22");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vdsm22-cli");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2010/08/19");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/17");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
  script_family(english:"Red Hat Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
os_ver = eregmatch(pattern: "Red Hat Enterprise Linux.*release ([0-9]+(\.[0-9]+)?)", string:release);
if (isnull(os_ver)) audit(AUDIT_UNKNOWN_APP_VER, "Red Hat");
os_ver = os_ver[1];
if (! ereg(pattern:"^5([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 5.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2010:0628";
  yum_report = redhat_generate_yum_updateinfo_report(rhsa:rhsa);
  if (!empty_or_null(yum_report))
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : yum_report 
    );
    exit(0);
  }
  else
  {
    audit_message = "affected by Red Hat security advisory " + rhsa;
    audit(AUDIT_OS_NOT, audit_message);
  }
}
else
{
  flag = 0;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vdsm22-4.5-62.14.el5_5rhev2_2")) flag++;
  if (rpm_check(release:"RHEL5", cpu:"x86_64", reference:"vdsm22-cli-4.5-62.14.el5_5rhev2_2")) flag++;

  if (flag)
  {
    security_report_v4(
      port       : 0,
      severity   : SECURITY_WARNING,
      extra      : rpm_report_get() + redhat_report_package_caveat()
    );
    exit(0);
  }
  else
  {
    tested = pkg_tests_get();
    if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vdsm22 / vdsm22-cli");
  }
}
