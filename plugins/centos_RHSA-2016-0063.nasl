#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:0063 and 
# CentOS Errata and Security Advisory 2016:0063 respectively.
#

include("compat.inc");

if (description)
{
  script_id(88147);
  script_version("$Revision: 2.8 $");
  script_cvs_date("$Date: 2017/02/13 20:44:58 $");

  script_cve_id("CVE-2015-8138");
  script_osvdb_id(133383);
  script_xref(name:"RHSA", value:"2016:0063");

  script_name(english:"CentOS 6 / 7 : ntp (CESA-2016:0063)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ntp packages that fix one security issue are now available for
Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Important
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

The Network Time Protocol (NTP) is used to synchronize a computer's
time with a referenced time source.

It was discovered that ntpd as a client did not correctly check the
originate timestamp in received packets. A remote attacker could use
this flaw to send a crafted packet to an ntpd client that would
effectively disable synchronization with the server, or push arbitrary
offset/delay measurements to modify the time on the client.
(CVE-2015-8138)

All ntp users are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing the
update, the ntpd daemon will restart automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021623.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?069c5223"
  );
  # http://lists.centos.org/pipermail/centos-announce/2016-January/021624.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1e3a3dd6"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ntp packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:N/I:L/A:N");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:F/RL:O/RC:X");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntp-perl");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ntpdate");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:sntp");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/01/25");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/01/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"ntp-4.2.6p5-5.el6.centos.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-doc-4.2.6p5-5.el6.centos.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntp-perl-4.2.6p5-5.el6.centos.4")) flag++;
if (rpm_check(release:"CentOS-6", reference:"ntpdate-4.2.6p5-5.el6.centos.4")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-4.2.6p5-22.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-doc-4.2.6p5-22.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntp-perl-4.2.6p5-22.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"ntpdate-4.2.6p5-22.el7.centos.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"sntp-4.2.6p5-22.el7.centos.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
