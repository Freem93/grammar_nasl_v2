#
# (C) Tenable Network Security, Inc.
#
# The descriptive text is (C) Scientific Linux.
#

if (NASL_LEVEL < 3000) exit(0);

include("compat.inc");

if (description)
{
  script_id(63592);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/04/02 10:44:39 $");

  script_cve_id("CVE-2012-3359");

  script_name(english:"Scientific Linux Security Update : conga on SL5.x i386/x86_64");
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
"It was discovered that luci stored usernames and passwords in session
cookies. This issue prevented the session inactivity timeout feature
from working correctly, and allowed attackers able to get access to a
session cookie to obtain the victim's authentication credentials.
(CVE-2012-3359)

This update also fixes the following bugs :

  - Prior to this update, luci did not allow the
    fence_apc_snmp agent to be configured. As a consequence,
    users could not configure or view an existing
    configuration for fence_apc_snmp. This update adds a new
    screen that allows fence_apc_snmp to be configured.

  - Prior to this update, luci did not allow the SSL
    operation of the fence_ilo fence agent to be enabled or
    disabled. As a consequence, users could not configure or
    view an existing configuration for the 'ssl' attribute
    for fence_ilo. This update adds a checkbox to show
    whether the SSL operation is enabled and allows users to
    edit that attribute.

  - Prior to this update, luci did not allow the
    'identity_file' attribute of the fence_ilo_mp fence
    agent to be viewed or edited. As a consequence, users
    could not configure or view an existing configuration
    for the 'identity_file' attribute of the fence_ilo_mp
    fence agent. This update adds a text input box to show
    the current state of the 'identity_file' attribute of
    fence_ilo_mp and allows users to edit that attribute.

  - Prior to this update, redundant files and directories
    remained on the file system at /var/lib/luci/var/pts and
    /usr/lib{,64}/luci/zope/var/pts when the luci package
    was uninstalled. This update removes these files and
    directories when the luci package is uninstalled.

  - Prior to this update, the 'restart-disable' recovery
    policy was not displayed in the recovery policy list
    from which users could select when they configure a
    recovery policy for a failover domain. As a consequence,
    the 'restart-disable' recovery policy could not be set
    with the luci GUI. This update adds the
    'restart-disable' recovery option to the recovery policy
    pulldown list.

  - Prior to this update, line breaks that were not
    anticipated in the 'yum list' output could cause package
    upgrade and/or installation to fail when creating
    clusters or adding nodes to existing clusters. As a
    consequence, creating clusters and adding cluster nodes
    to existing clusters could fail. This update modifies
    the ricci daemon to be able to correctly handle line
    breaks in the 'yum list' output.

In addition, this update adds the following enhancements :

  - This update adds support for configuring the Intel iPDU
    fence agent to the luci package.

  - This update adds support for viewing and changing the
    state of the new 'nfsrestart' attribute to the FS and
    Cluster FS resource agent configuration screens.

After installing this update, the luci and ricci services will be
restarted automatically."
  );
  # http://listserv.fnal.gov/scripts/wa.exe?A2=ind1301&L=scientific-linux-errata&T=0&P=1456
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?552cec6b"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected conga-debuginfo, luci and / or ricci packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"x-cpe:/o:fermilab:scientific_linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/17");
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
if (rpm_check(release:"SL5", reference:"conga-debuginfo-0.12.2-64.el5")) flag++;
if (rpm_check(release:"SL5", reference:"luci-0.12.2-64.el5")) flag++;
if (rpm_check(release:"SL5", reference:"ricci-0.12.2-64.el5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
