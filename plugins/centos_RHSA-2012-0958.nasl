#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2012:0958 and 
# CentOS Errata and Security Advisory 2012:0958 respectively.
#

include("compat.inc");

if (description)
{
  script_id(59933);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2016/08/22 14:13:26 $");

  script_cve_id("CVE-2012-2664");
  script_osvdb_id(83550);
  script_xref(name:"RHSA", value:"2012:0958");

  script_name(english:"CentOS 6 : sos (CESA-2012:0958)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated sos package that fixes one security issue, several bugs,
and adds various enhancements is now available for Red Hat Enterprise
Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The sos package contains a set of tools that gather information from
system hardware, logs and configuration files. The information can
then be used for diagnostic purposes and debugging.

The sosreport utility collected the Kickstart configuration file
('/root/anaconda-ks.cfg'), but did not remove the root user's password
from it before adding the file to the resulting archive of debugging
information. An attacker able to access the archive could possibly use
this flaw to obtain the root user's password. '/root/anaconda-ks.cfg'
usually only contains a hash of the password, not the plain text
password. (CVE-2012-2664)

Note: This issue affected all installations, not only systems
installed via Kickstart. A '/root/anaconda-ks.cfg' file is created by
all installation types.

This updated sos package also includes numerous bug fixes and
enhancements. Space precludes documenting all of these changes in this
advisory. Users are directed to the Red Hat Enterprise Linux 6.3
Technical Notes for information on the most significant of these
changes.

All users of sos are advised to upgrade to this updated package, which
contains backported patches to correct these issues and add these
enhancements."
  );
  # http://lists.centos.org/pipermail/centos-announce/2012-July/018723.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?790a652f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected sos package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sos");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"plugin_publication_date", value:"2012/07/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2012-2016 Tenable Network Security, Inc.");
  script_family(english:"CentOS Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/CentOS/release", "Host/CentOS/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/CentOS/release")) audit(AUDIT_OS_NOT, "CentOS");
if (!get_kb_item("Host/CentOS/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-6", reference:"sos-2.2-29.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
