#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2005:673 and 
# CentOS Errata and Security Advisory 2005:673 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67030);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2005-1704");
  script_xref(name:"RHSA", value:"2005:673");

  script_name(english:"CentOS 4 : binutils (CESA-2005:673)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"An updated binutils package that fixes several bugs and minor security
issues is now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

Binutils is a collection of utilities used for the creation of
executable code. A number of bugs were found in various binutils
tools.

If a user is tricked into processing a specially crafted executable
with utilities such as readelf, size, strings, objdump, or nm, it may
allow the execution of arbitrary code as the user. The Common
Vulnerabilities and Exposures project (cve.mitre.org) has assigned the
name CVE-2005-1704 to this issue.

In addition, the following bugs have been fixed :

-- by default issue an error if IA-64 hint@pause instruction is put
into the B slot, add assembler command line switch to override this
behaviour -- fix linker's --emit-relocs with .gnu.warning.* section
symbols -- fix gprof on 64-bit ppc binaries and libraries -- fix gas
mapping of register names to dwarf2 register numbers in CFI directives

All users of binutils should upgrade to this updated package, which
contains patches to resolve these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2005-October/012240.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b099e757"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected binutils package."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:binutils");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2005/10/05");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013 Tenable Network Security, Inc.");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"binutils-2.15.92.0.2-15")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
