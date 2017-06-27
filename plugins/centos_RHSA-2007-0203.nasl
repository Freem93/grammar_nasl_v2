#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were  
# extracted from Red Hat Security Advisory RHSA-2007:0203 and 
# CentOS Errata and Security Advisory 2007:0203 respectively.
#

include("compat.inc");

if (description)
{
  script_id(67039);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2013/06/29 00:08:47 $");

  script_cve_id("CVE-2005-2475", "CVE-2005-4667");
  script_bugtraq_id(14450);
  script_osvdb_id(18530, 19952, 22194, 22400, 24315, 25848, 27380, 28318, 28464, 35692, 35693, 39165);
  script_xref(name:"RHSA", value:"2007:0203");

  script_name(english:"CentOS 4 : unzip (CESA-2007:0203)");
  script_summary(english:"Checks rpm output for the updated package");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote CentOS host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Updated unzip packages that fix two security issues and various bugs
are now available.

This update has been rated as having low security impact by the Red
Hat Security Response Team.

The unzip utility is used to list, test, or extract files from a zip
archive.

A race condition was found in Unzip. Local users could use this flaw
to modify permissions of arbitrary files via a hard link attack on a
file while it was being decompressed (CVE-2005-2475)

A buffer overflow was found in Unzip command line argument handling.
If a user could be tricked into running Unzip with a specially crafted
long file name, an attacker could execute arbitrary code with that
user's privileges. (CVE-2005-4667)

As well, this update adds support for files larger than 2GB.

All users of unzip should upgrade to these updated packages, which
contain backported patches that resolve these issues."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.centos.org/pipermail/centos-announce/2007-May/013709.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected unzip package.");
  script_set_cvss_base_vector("CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:F/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_cwe_id(119);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:centos:centos:unzip");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:centos:centos:4");

  script_set_attribute(attribute:"patch_publication_date", value:"2007/05/02");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/06/28");
  script_set_attribute(attribute:"vuln_publication_date", value:"2005/08/01");
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
if (rpm_check(release:"CentOS-4", cpu:"ia64", reference:"unzip-5.51-9.EL4.5")) flag++;


if (flag)
{
  if (report_verbosity > 0) security_note(port:0, extra:rpm_report_get());
  else security_note(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
