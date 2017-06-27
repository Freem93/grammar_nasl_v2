#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0549. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(97844);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/28 13:31:42 $");

  script_cve_id("CVE-2016-9577", "CVE-2016-9578");
  script_osvdb_id(151470, 151473);
  script_xref(name:"RHSA", value:"2017:0549");

  script_name(english:"RHEL 7 : redhat-virtualization-host (RHSA-2017:0549)");
  script_summary(english:"Checks the rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for imgbased, redhat-release-virtualization-host, and
redhat-virtualization-host is now available for RHEV 4.X, RHEV-H, and
Agents for RHEL-7.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The redhat-virtualization-host packages provide the Red Hat
Virtualization Host. These packages include
redhat-release-virtualization-host, ovirt-node, and rhev-hypervisor.
Red Hat Virtualization Hosts (RHVH) are installed using a special
build of Red Hat Enterprise Linux with only the packages required to
host virtual machines. RHVH features a Cockpit user interface for
monitoring the host's resources and performing administrative tasks.

The following packages have been upgraded to a later upstream version:
redhat-release-virtualization-host (4.0), imgbased (0.8.16),
redhat-virtualization-host (4.0). (BZ#1410848, BZ#1430244)

Security Fix(es) :

* A vulnerability was discovered in SPICE in the server's protocol
handling. An authenticated attacker could send crafted messages to the
SPICE server causing a heap overflow leading to a crash or possible
code execution. (CVE-2016-9577)

* A vulnerability was discovered in SPICE in the server's protocol
handling. An attacker able to connect to the SPICE server could send
crafted messages which would cause the process to crash.
(CVE-2016-9578)

These issues were discovered by Frediano Ziglio (Red Hat).

Bug Fix(es) :

* Previously, imgbased blindly copied /etc from old layers into new
layers in order to keep configuration changes between upgrades. This
meant that imgbased's behavior differed from RPM, in that unmodified
configuration files would be preserved across imgbased upgrades
whereas 'yum upgrade' of the same packages would have replaced them.
Now, imgbased compares the sums of files to the originals kept
per-layer in /usr/share/factory/etc so that unmodified configuration
files are now handled appropriately. (BZ#1418179)

* Previously, some earlier versions of Red Hat Virtualization Host
(RHVH) repeatedly prompted for upgrades, even when the most recent
version was already installed. This was caused by the RHVH image
containing a placeholder package that was made obsolete in order to
upgrade. However, the package that was used to upgrade was not
propagated to the rpmdb on the new image. Now, upgrading includes the
update package in the rpmdb on the new image. (BZ#1422476)

* With this update, Red Hat Virtualization Host (RHVH) now includes
the 'screen' package. Previously, ovirt-hosted-engine-setup invoked
from a CLI warned users that the 'screen' package was not installed.
Though this was not an explicit requirement when using cockpit,
including it provides a better experience if using the CLI.
(BZ#1403729)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9577.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2016-9578.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2017-0549.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected redhat-virtualization-host-image-update package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:redhat-virtualization-host-image-update");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/21");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^7([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 7.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2017:0549";
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
  if (rpm_check(release:"RHEL7", reference:"redhat-virtualization-host-image-update-4.0-20170307.1.el7_3")) flag++;

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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "redhat-virtualization-host-image-update");
  }
}
