#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0960 and 
# CentOS Errata and Security Advisory 2007:0960 respectively.
#

include("compat.inc");

if (description)
{
  script_id(43657);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2015/05/19 23:34:17 $");

  script_cve_id("CVE-2007-5208");
  script_bugtraq_id(26054);
  script_osvdb_id(41693);
  script_xref(name:"RHSA", value:"2007:0960");

  script_name(english:"CentOS 5 : hplip (CESA-2007:0960)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated hplip package to correct a security flaw is now available
for Red Hat Enterprise Linux 5.

This update has been rated as having important security impact by the
Red Hat Security Response Team.

The hplip (Hewlett-Packard Linux Imaging and Printing Project) package
provides drivers for HP printers and multi-function peripherals.

Kees Cook discovered a flaw in the way the hplip hpssd daemon handled
user input. A local attacker could send a specially crafted request to
the hpssd daemon, possibly allowing them to run arbitrary commands as
the root user. (CVE-2007-5208). On Red Hat Enterprise Linux 5, the
SELinux targeted policy for hpssd which is enabled by default, blocks
the ability to exploit this issue to run arbitrary code.

Users of hplip are advised to upgrade to this updated package, which
contains backported patches to resolve this issue."
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014296.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?02bdc6a5"
  );
  # http://lists.centos.org/pipermail/centos-announce/2007-October/014297.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?82d708f8"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected hplip packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'HPLIP hpssd.py From Address Arbitrary Command Execution');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'D2ExploitPack');
  script_cwe_id(20);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hpijs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:hplip");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsane-hpaio");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/10/13");
  script_set_attribute(attribute:"plugin_publication_date", value:"2010/01/06");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2010-2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-5", reference:"hpijs-1.6.7-4.1.el5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"hplip-1.6.7-4.1.el5.3")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsane-hpaio-1.6.7-4.1.el5.3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
