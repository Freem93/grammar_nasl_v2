#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2015:0700 and 
# CentOS Errata and Security Advisory 2015:0700 respectively.
#

include("compat.inc");

if (description)
{
  script_id(81925);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2015/05/19 23:59:33 $");

  script_cve_id("CVE-2014-8139", "CVE-2014-8140", "CVE-2014-8141", "CVE-2014-9636");
  script_bugtraq_id(71790, 71792, 71793, 71825);
  script_xref(name:"RHSA", value:"2015:0700");

  script_name(english:"CentOS 6 / 7 : unzip (CESA-2015:0700)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated unzip packages that fix multiple security issues are now
available for Red Hat Enterprise Linux 6 and 7.

Red Hat Product Security has rated this update as having Moderate
security impact. Common Vulnerability Scoring System (CVSS) base
scores, which give detailed severity ratings, are available for each
vulnerability from the CVE links in the References section.

The unzip utility is used to list, test, or extract files from a zip
archive.

A buffer overflow was found in the way unzip uncompressed certain
extra fields of a file. A specially crafted Zip archive could cause
unzip to crash or, possibly, execute arbitrary code when the archive
was tested with unzip's '-t' option. (CVE-2014-9636)

A buffer overflow flaw was found in the way unzip computed the CRC32
checksum of certain extra fields of a file. A specially crafted Zip
archive could cause unzip to crash when the archive was tested with
unzip's '-t' option. (CVE-2014-8139)

An integer underflow flaw, leading to a buffer overflow, was found in
the way unzip uncompressed certain extra fields of a file. A specially
crafted Zip archive could cause unzip to crash when the archive was
tested with unzip's '-t' option. (CVE-2014-8140)

A buffer overflow flaw was found in the way unzip handled Zip64 files.
A specially crafted Zip archive could possibly cause unzip to crash
when the archive was uncompressed. (CVE-2014-8141)

Red Hat would like to thank oCERT for reporting the CVE-2014-8139,
CVE-2014-8140, and CVE-2014-8141 issues. oCERT acknowledges Michele
Spagnuolo of the Google Security Team as the original reporter of
these issues.

All unzip users are advised to upgrade to these updated packages,
which contain backported patches to correct these issues."
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-April/021042.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?7622cb50"
  );
  # http://lists.centos.org/pipermail/centos-announce/2015-March/020981.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?f9a75bb3"
  );
  # http://lists.centos.org/pipermail/centos-cr-announce/2015-March/001856.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?3fb46828"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected unzip package.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:6");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:7");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/03/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
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
if (rpm_check(release:"CentOS-6", reference:"unzip-6.0-2.el6_6")) flag++;

if (rpm_check(release:"CentOS-7", cpu:"x86_64", reference:"unzip-6.0-15.el7")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
