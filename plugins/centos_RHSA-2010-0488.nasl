#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2010:0488 and 
# CentOS Errata and Security Advisory 2010:0488 respectively.
#

include("compat.inc");

if (description)
{
  script_id(47101);
  script_version("$Revision: 1.13 $");
  script_cvs_date("$Date: 2015/05/19 23:43:07 $");

  script_cve_id("CVE-2010-2063");
  script_osvdb_id(65518);
  script_xref(name:"RHSA", value:"2010:0488");

  script_name(english:"CentOS 3 / 4 / 5 : samba / samba3x (CESA-2010:0488)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated samba and samba3x packages that fix one security issue are now
available for Red Hat Enterprise Linux 3, 4, and 5, and Red Hat
Enterprise Linux 4.7, 5.3, and 5.4 Extended Update Support.

The Red Hat Security Response Team has rated this update as having
critical security impact. A Common Vulnerability Scoring System (CVSS)
base score, which gives a detailed severity rating, is available from
the CVE link in the References section.

Samba is a suite of programs used by machines to share files,
printers, and other information.

An input sanitization flaw was found in the way Samba parsed client
data. A malicious client could send a specially crafted SMB packet to
the Samba server, resulting in arbitrary code execution with the
privileges of the Samba server (smbd). (CVE-2010-2063)

Red Hat would like to thank the Samba team for responsibly reporting
this issue. Upstream acknowledges Jun Mao as the original reporter.

Users of Samba are advised to upgrade to these updated packages, which
contain a backported patch to resolve this issue. After installing
this update, the smb service will be restarted automatically."
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016910.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bf85541e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-August/016911.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?949aa292"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016787.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?637edd8e"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-July/016788.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b7b8e1bc"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-June/016733.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?972b2d40"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-June/016734.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?950b07f8"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-June/016737.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?531ccc2d"
  );
  # http://lists.centos.org/pipermail/centos-announce/2010-June/016738.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bea8f4c6"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected samba and / or samba3x packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Samba chain_reply Memory Corruption (Linux x86)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libsmbclient-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtalloc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtalloc-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtdb");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:libtdb-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-client");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-common");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-domainjoin-gui");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-swat");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:samba3x-winbind-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:tdb-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:3");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:5");

  script_set_attribute(attribute:"plugin_publication_date", value:"2010/06/21");
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
if ("x86_64" >!< cpu && "ia64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "CentOS", cpu);


flag = 0;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-client-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-client-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-common-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-common-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"i386", reference:"samba-swat-3.0.9-1.3E.17")) flag++;
if (rpm_check(release:"CentOS-3", cpu:"x86_64", reference:"samba-swat-3.0.9-1.3E.17")) flag++;

if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-client-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-client-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-common-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-common-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"i386", reference:"samba-swat-3.0.33-0.19.el4_8.1")) flag++;
if (rpm_check(release:"CentOS-4", cpu:"x86_64", reference:"samba-swat-3.0.33-0.19.el4_8.1")) flag++;

if (rpm_check(release:"CentOS-5", reference:"libsmbclient-3.0.33-3.29.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libsmbclient-devel-3.0.33-3.29.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtalloc-1.2.0-52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtalloc-devel-1.2.0-52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtdb-1.1.2-52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"libtdb-devel-1.1.2-52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-3.0.33-3.29.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-client-3.0.33-3.29.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-common-3.0.33-3.29.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba-swat-3.0.33-3.29.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-client-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-common-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-doc-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-domainjoin-gui-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-swat-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"samba3x-winbind-devel-3.3.8-0.52.el5_5")) flag++;
if (rpm_check(release:"CentOS-5", reference:"tdb-tools-1.1.2-52.el5_5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
