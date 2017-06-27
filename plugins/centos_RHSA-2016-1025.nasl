#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2016:1025 and 
# CentOS Errata and Security Advisory 2016:1025 respectively.
#

include("compat.inc");

if (description)
{
  script_id(91104);
  script_version("$Revision: 2.3 $");
  script_cvs_date("$Date: 2016/11/17 21:12:11 $");

  script_cve_id("CVE-2015-2328", "CVE-2015-3217", "CVE-2015-5073", "CVE-2015-8385", "CVE-2015-8386", "CVE-2015-8388", "CVE-2015-8391", "CVE-2016-3191");
  script_osvdb_id(109910, 122901, 123810, 131058, 131059, 131061, 131064, 134395);
  script_xref(name:"RHSA", value:"2016:1025");

  script_name(english:"CentOS 7 : pcre (CESA-2016:1025)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An update for pcre is now available for Red Hat Enterprise Linux 7.

Red Hat Product Security has rated this update as having a security
impact of Important. A Common Vulnerability Scoring System (CVSS) base
score, which gives a detailed severity rating, is available for each
vulnerability from the CVE link(s) in the References section.

PCRE is a Perl-compatible regular expression library.

Security Fix(es) :

* Multiple flaws were found in the way PCRE handled malformed regular
expressions. An attacker able to make an application using PCRE
process a specially crafted regular expression could use these flaws
to cause the application to crash or, possibly, execute arbitrary
code. (CVE-2015-8385, CVE-2016-3191, CVE-2015-2328, CVE-2015-3217,
CVE-2015-5073, CVE-2015-8388, CVE-2015-8391, CVE-2015-8386)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2016-May/021883.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected pcre packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:U/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre-static");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:pcre-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/05/12");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/05/13");
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
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pcre-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pcre-devel-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pcre-static-8.32-15.el7_2.1")) flag++;
if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"pcre-tools-8.32-15.el7_2.1")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
