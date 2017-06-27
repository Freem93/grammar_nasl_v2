#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2017:0837 and 
# CentOS Errata and Security Advisory 2017:0837 respectively.
#

include("compat.inc");

if (description)
{
  script_id(99040);
  script_version("$Revision: 3.1 $");
  script_cvs_date("$Date: 2017/03/30 13:31:43 $");

  script_cve_id("CVE-2017-5208", "CVE-2017-5332", "CVE-2017-5333", "CVE-2017-6009", "CVE-2017-6010", "CVE-2017-6011");
  script_osvdb_id(149763, 149764, 151916, 152182, 152183);
  script_xref(name:"RHSA", value:"2017:0837");

  script_name(english:"CentOS 7 : icoutils (CESA-2017:0837)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for icoutils is now available for Red Hat Enterprise Linux
7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

The icoutils are a set of programs for extracting and converting
images in Microsoft Windows icon and cursor files. These files usually
have the extension .ico or .cur, but they can also be embedded in
executables or libraries.

Security Fix(es) :

* Multiple vulnerabilities were found in icoutils, in the wrestool
program. An attacker could create a crafted executable that, when read
by wrestool, could result in memory corruption leading to a crash or
potential code execution. (CVE-2017-5208, CVE-2017-5333,
CVE-2017-6009)

* A vulnerability was found in icoutils, in the wrestool program. An
attacker could create a crafted executable that, when read by
wrestool, could result in failure to allocate memory or an over-large
memcpy operation, leading to a crash. (CVE-2017-5332)

* Multiple vulnerabilities were found in icoutils, in the icotool
program. An attacker could create a crafted ICO or CUR file that, when
read by icotool, could result in memory corruption leading to a crash
or potential code execution. (CVE-2017-6010, CVE-2017-6011)"
  );
  # http://lists.centos.org/pipermail/centos-announce/2017-March/022347.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?26217a60"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected icoutils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:N/UI:R/S:U/C:N/I:N/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:icoutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/03/29");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/03/30");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"icoutils-0.31.3-1.el7_3")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
