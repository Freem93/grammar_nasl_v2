#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Oracle Linux Security Advisories ELSA-2006-0604 / 
# ELSA-2006-0729.
#

include("compat.inc");

if (description)
{
  script_id(67399);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/07/12 21:50:25 $");

  script_cve_id("CVE-2006-3694", "CVE-2006-5467");
  script_osvdb_id(11534, 27144, 34237);
  script_xref(name:"RHSA", value:"2006:0604");
  script_xref(name:"RHSA", value:"2006:0729");

  script_name(english:"Oracle Linux 3 / 4 : ruby (ELSA-2006-0604 / ELSA-2006-0729)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Oracle Linux host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated ruby packages that fix security issues are now available. 

This update has been rated as having moderate security impact by the Red
Hat Security Response Team. 

Ruby is an interpreted scripting language for object-oriented
programming. 

Users of Ruby should upgrade to these updated packages which contain
backported patches and are not vulnerable to these issues. 


From Red Hat Security Advisory 2006:0604 :

A number of flaws were found in the safe-level restrictions in Ruby.  It
was possible for an attacker to create a carefully crafted malicious
script that can allow the bypass of certain safe-level restrictions. 
(CVE-2006-3694)


From Red Hat Security Advisory 2006:0729 :

A flaw was discovered in the way Ruby's CGI module handles certain
multipart/form-data MIME data.  If a remote attacker sends a specially
crafted multipart-form-data request, it is possible to cause the ruby
CGI script to enter an infinite loop, causing a denial of service. 
(CVE-2006-5467)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/el-errata/2006-November/000018.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected ruby packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:N");

  script_set_attribute(attribute:"patch_publication_date", value:"2006/11/30");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/07/12");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:irb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-docs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-libs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-mode");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:linux:ruby-tcltk");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:linux:4");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
  script_family(english:"Oracle Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleLinux", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/OracleLinux")) audit(AUDIT_OS_NOT, "Oracle Linux");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Oracle Linux", cpu);


flag = 0;
if (rpm_check(release:"EL4", cpu:"i386", reference:"irb-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"irb-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-devel-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-devel-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-docs-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-docs-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-libs-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-libs-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-mode-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-mode-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"i386", reference:"ruby-tcltk-1.8.1-7.EL4.8")) flag++;
if (rpm_check(release:"EL4", cpu:"x86_64", reference:"ruby-tcltk-1.8.1-7.EL4.8")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");

