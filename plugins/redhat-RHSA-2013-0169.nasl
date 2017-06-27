#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0169. The text 
# itself is copyright (C) Red Hat, Inc.
#

include("compat.inc");

if (description)
{
  script_id(63641);
  script_version ("$Revision: 1.12 $");
  script_cvs_date("$Date: 2017/01/05 16:17:30 $");

  script_cve_id("CVE-2011-0904", "CVE-2011-0905", "CVE-2011-1164", "CVE-2011-1165", "CVE-2012-4429");
  script_bugtraq_id(47681, 55548);
  script_osvdb_id(74332, 74333, 85527, 89520, 89521);
  script_xref(name:"RHSA", value:"2013:0169");

  script_name(english:"RHEL 6 : vino (RHSA-2013:0169)");
  script_summary(english:"Checks the rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Red Hat host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated vino package that fixes several security issues is now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. Common Vulnerability Scoring System (CVSS)
base scores, which give detailed severity ratings, are available for
each vulnerability from the CVE links in the References section.

Vino is a Virtual Network Computing (VNC) server for GNOME. It allows
remote users to connect to a running GNOME session using VNC.

It was found that Vino transmitted all clipboard activity on the
system running Vino to all clients connected to port 5900, even those
who had not authenticated. A remote attacker who is able to access
port 5900 on a system running Vino could use this flaw to read
clipboard data without authenticating. (CVE-2012-4429)

Two out-of-bounds memory read flaws were found in the way Vino
processed client framebuffer requests in certain encodings. An
authenticated client could use these flaws to send a specially crafted
request to Vino, causing it to crash. (CVE-2011-0904, CVE-2011-0905)

In certain circumstances, the vino-preferences dialog box incorrectly
indicated that Vino was only accessible from the local network. This
could confuse a user into believing connections from external networks
are not allowed (even when they are allowed). With this update,
vino-preferences no longer displays connectivity and reachable
information. (CVE-2011-1164)

There was no warning that Universal Plug and Play (UPnP) was used to
open ports on a user's network router when the 'Configure network
automatically to accept connections' option was enabled (it is
disabled by default) in the Vino preferences. This update changes the
option's description to avoid the risk of a UPnP router configuration
change without the user's consent. (CVE-2011-1165)

All Vino users should upgrade to this updated package, which contains
backported patches to resolve these issues. The GNOME session must be
restarted (log out, then log back in) for this update to take effect."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0904.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-0905.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1164.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2011-1165.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.redhat.com/security/data/cve/CVE-2012-4429.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://rhn.redhat.com/errata/RHSA-2013-0169.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected vino and / or vino-debuginfo packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vino");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:redhat:enterprise_linux:vino-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:redhat:enterprise_linux:6.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/01/21");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/01/22");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^6([^0-9]|$)", string:os_ver)) audit(AUDIT_OS_NOT, "Red Hat 6.x", "Red Hat " + os_ver);

if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "s390" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

yum_updateinfo = get_kb_item("Host/RedHat/yum-updateinfo");
if (!empty_or_null(yum_updateinfo)) 
{
  rhsa = "RHSA-2013:0169";
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
  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vino-2.28.1-8.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vino-2.28.1-8.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vino-2.28.1-8.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"i686", reference:"vino-debuginfo-2.28.1-8.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"s390x", reference:"vino-debuginfo-2.28.1-8.el6_3")) flag++;

  if (rpm_check(release:"RHEL6", cpu:"x86_64", reference:"vino-debuginfo-2.28.1-8.el6_3")) flag++;


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
    else audit(AUDIT_PACKAGE_NOT_INSTALLED, "vino / vino-debuginfo");
  }
}
