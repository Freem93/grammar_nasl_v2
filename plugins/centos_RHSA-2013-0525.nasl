#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0525 and 
# CentOS Errata and Security Advisory 2013:0525 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65155);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2010-4531");
  script_bugtraq_id(45450);
  script_osvdb_id(69974);
  script_xref(name:"RHSA", value:"2013:0525");

  script_name(english:"CentOS 6 : pcsc-lite (CESA-2013:0525)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated pcsc-lite packages that fix one security issue and three bugs
are now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
moderate security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

PC/SC Lite provides a Windows SCard compatible interface for
communicating with smart cards, smart card readers, and other security
tokens.

A stack-based buffer overflow flaw was found in the way pcsc-lite
decoded certain attribute values of Answer-to-Reset (ATR) messages. A
local attacker could use this flaw to execute arbitrary code with the
privileges of the user running the pcscd daemon (root, by default), by
inserting a specially crafted smart card. (CVE-2010-4531)

This update also fixes the following bugs :

* Due to an error in the init script, the chkconfig utility did not
automatically place the pcscd init script after the start of the HAL
daemon. Consequently, the pcscd service did not start automatically at
boot time. With this update, the pcscd init script has been changed to
explicitly start only after HAL is up, thus fixing this bug.
(BZ#788474, BZ#814549)

* Because the chkconfig settings and the startup files in the
/etc/rc.d/ directory were not changed during the update described in
the RHBA-2012:0990 advisory, the user had to update the chkconfig
settings manually to fix the problem. Now, the chkconfig settings and
the startup files in the /etc/rc.d/ directory are automatically
updated as expected. (BZ#834803)

* Previously, the SCardGetAttrib() function did not work properly and
always returned the 'SCARD_E_INSUFFICIENT_BUFFER' error regardless of
the actual buffer size. This update applies a patch to fix this bug
and the SCardGetAttrib() function now works as expected. (BZ#891852)

All users of pcsc-lite are advised to upgrade to these updated
packages, which fix these issues. After installing this update, the
pcscd daemon will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019466.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d2700de1"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000657.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?1dfe6aab"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected pcsc-lite packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcsc-lite-libs");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"pcsc-lite-1.5.2-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pcsc-lite-devel-1.5.2-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pcsc-lite-doc-1.5.2-11.el6")) flag++;
if (rpm_check(release:"CentOS-6", reference:"pcsc-lite-libs-1.5.2-11.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
