#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0428 and 
# CentOS Errata and Security Advisory 2016:0428 respectively.
#

include("compat.inc");

if (description)
{
  script_id(89849);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2016/11/17 21:12:10 $");

  script_cve_id("CVE-2016-0787");
  script_osvdb_id(134850);
  script_xref(name:"RHSA", value:"2016:0428");

  script_name(english:"CentOS 6 / 7 : libssh2 (CESA-2016:0428)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated libssh2 packages that fix one security issue are now available
for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The libssh2 packages provide a library that implements the SSHv2
protocol.

A type confusion issue was found in the way libssh2 generated
ephemeral secrets for the diffie-hellman-group1 and
diffie-hellman-group14 key exchange methods. This would cause an SSHv2
Diffie-Hellman handshake to use significantly less secure random
parameters. (CVE-2016-0787)

Red Hat would like to thank Aris Adamantiadis for reporting this
issue.

All libssh2 users are advised to upgrade to these updated packages,
which contain a backported patch to correct this issue. After
installing these updated packages, all running applications using
libssh2 must be restarted for this update to take effect."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-March/021726.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?8a641326"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-March/021727.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?e76358c2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libssh2 packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:H/PR:N/UI:N/S:U/C:H/I:N/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libssh2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libssh2-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libssh2-docs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/03/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/03/11");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"libssh2-1.4.2-2.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libssh2-devel-1.4.2-2.el6_7.1")) flag++;
if (rpm_check(release:"CentOS-6", reference:"libssh2-docs-1.4.2-2.el6_7.1")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libssh2-1.4.3-10.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libssh2-devel-1.4.3-10.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"libssh2-docs-1.4.3-10.el7_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
