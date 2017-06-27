#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0523 and 
# CentOS Errata and Security Advisory 2013:0523 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65154);
  script_version("$Revision: 1.6 $");
  script_cvs_date("$Date: 2015/05/19 23:52:01 $");

  script_cve_id("CVE-2010-4530");
  script_bugtraq_id(45806);
  script_xref(name:"RHSA", value:"2013:0523");

  script_name(english:"CentOS 6 : ccid (CESA-2013:0523)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated ccid package that fixes one security issue and one bug are
now available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having low
security impact. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available from the
CVE link in the References section.

Chip/Smart Card Interface Devices (CCID) is a USB smart card reader
standard followed by most modern smart card readers. The ccid package
provides a Generic, USB-based CCID driver for readers, which follow
this standard.

An integer overflow, leading to an array index error, was found in the
way the CCID driver processed a smart card's serial number. A local
attacker could use this flaw to execute arbitrary code with the
privileges of the user running the PC/SC Lite pcscd daemon (root, by
default), by inserting a specially crafted smart card. (CVE-2010-4530)

This update also fixes the following bug :

* Previously, CCID only recognized smart cards with 5V power supply.
With this update, CCID also supports smart cards with different power
supply. (BZ#808115)

All users of ccid are advised to upgrade to this updated package,
which contains backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019294.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?d1cb3d2e"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-February/000485.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?0896496f"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ccid package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:ccid");
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
if (rpm_check(release:"CentOS-6", reference:"ccid-1.3.9-6.el6")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
