#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0725 and 
# CentOS Errata and Security Advisory 2017:0725 respectively.
#

include("compat.inc");

if (description)
{
  script_id(97959);
  script_version("$Revision: 3.2 $");
  script_cvs_date("$Date: 2017/03/27 19:45:56 $");

  script_cve_id("CVE-2016-0634", "CVE-2016-7543", "CVE-2016-9401");
  script_xref(name:"RHSA", value:"2017:0725");

  script_name(english:"CentOS 6 : bash (CESA-2017:0725)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for bash is now available for Red Hat Enterprise Linux 6.

Red Hat Product Security has rated this update as having a security
impact of Moderate. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The bash packages provide Bash (Bourne-again shell), which is the
default shell for Red Hat Enterprise Linux.

Security Fix(es) :

* An arbitrary command injection flaw was found in the way bash
processed the hostname value. A malicious DHCP server could use this
flaw to execute arbitrary commands on the DHCP client machines running
bash under specific circumstances. (CVE-2016-0634)

* An arbitrary command injection flaw was found in the way bash
processed the SHELLOPTS and PS4 environment variables. A local,
authenticated attacker could use this flaw to exploit poorly written
setuid programs to elevate their privileges under certain
circumstances. (CVE-2016-7543)

* A denial of service flaw was found in the way bash handled popd
commands. A poorly written shell script could cause bash to crash
resulting in a local denial of service limited to a specific bash
session. (CVE-2016-9401)

Additional Changes :

For detailed information on changes in this release, see the Red Hat
Enterprise Linux 6.9 Release Notes and Red Hat Enterprise Linux 6.9
Technical Notes linked from the References section."
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2017-March/003724.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?97c2a33a"
  );
  script_set_attribute(attribute:"solution", value:
"Update the affected bash packages. Note that the updated packages
may not be immediately available from the package repository and its
mirrors.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bash");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:bash-doc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"bash-4.1.2-48.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"bash-doc-4.1.2-48.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
