#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2013:0590 and 
# CentOS Errata and Security Advisory 2013:0590 respectively.
#

include("compat.inc");

if (description)
{
  script_id(65161);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/05/04 14:39:52 $");

  script_cve_id("CVE-2013-0288");
  script_bugtraq_id(58007);
  script_osvdb_id(90327);
  script_xref(name:"RHSA", value:"2013:0590");

  script_name(english:"CentOS 6 : nss-pam-ldapd (CESA-2013:0590)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated nss-pam-ldapd packages that fix one security issue are now
available for Red Hat Enterprise Linux 6.

The Red Hat Security Response Team has rated this update as having
important security impact. A Common Vulnerability Scoring System
(CVSS) base score, which gives a detailed severity rating, is
available from the CVE link in the References section.

The nss-pam-ldapd packages provide the nss-pam-ldapd daemon (nslcd),
which uses a directory server to lookup name service information on
behalf of a lightweight nsswitch module.

An array index error, leading to a stack-based buffer overflow flaw,
was found in the way nss-pam-ldapd managed open file descriptors. An
attacker able to make a process have a large number of open file
descriptors and perform name lookups could use this flaw to cause the
process to crash or, potentially, execute arbitrary code with the
privileges of the user running the process. (CVE-2013-0288)

Red Hat would like to thank Garth Mollett for reporting this issue.

All users of nss-pam-ldapd are advised to upgrade to these updated
packages, which contain a backported patch to fix this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2013-March/019628.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?581738d7"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2013-March/000816.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?ab321c5e"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected nss-pam-ldapd package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:nss-pam-ldapd");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/03/08");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/03/10");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"nss-pam-ldapd-0.7.5-18.1.el6_4")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
