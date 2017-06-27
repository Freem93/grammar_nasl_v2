#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2015-0067.
#

include("compat.inc");

if (description)
{
  script_id(84139);
  script_version("$Revision: 2.5 $");
  script_cvs_date("$Date: 2017/02/14 17:16:24 $");

  script_cve_id("CVE-2015-3209", "CVE-2015-4163", "CVE-2015-4164");
  script_bugtraq_id(75123, 75141, 75149);
  script_osvdb_id(123147, 123237, 123281);

  script_name(english:"OracleVM 3.3 : xen (OVMSA-2015-0067)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates :

  - x86/traps: loop in the correct direction in compat_iret
    This is XSA-136. (CVE-2015-4164)

  - pcnet: force the buffer access to be in bounds during tx
    4096 is the maximum length per TMD and it is also
    currently the size of the relay buffer pcnet driver uses
    for sending the packet data to QEMU for further
    processing. With packet spanning multiple TMDs it can
    happen that the overall packet size will be bigger than
    sizeof(buffer), which results in memory corruption. Fix
    this by only allowing to queue maximum sizeof(buffer)
    bytes. This is CVE-2015-3209. (CVE-2015-3209)

  - pcnet: fix Negative array index read From: Gonglei
    s->xmit_pos maybe assigned to a negative value (-1), but
    in this branch variable s->xmit_pos as an index to array
    s->buffer. Let's add a check for s->xmit_pos.
    upstream-commit-id:
    7b50d00911ddd6d56a766ac5671e47304c20a21b (CVE-2015-3209)

  - pcnet: force the buffer access to be in bounds during tx
    4096 is the maximum length per TMD and it is also
    currently the size of the relay buffer pcnet driver uses
    for sending the packet data to QEMU for further
    processing. With packet spanning multiple TMDs it can
    happen that the overall packet size will be bigger than
    sizeof(buffer), which results in memory corruption. Fix
    this by only allowing to queue maximum sizeof(buffer)
    bytes. This is CVE-2015-3209. (CVE-2015-3209)

  - pcnet: fix Negative array index read From: Gonglei
    s->xmit_pos maybe assigned to a negative value (-1), but
    in this branch variable s->xmit_pos as an index to array
    s->buffer. Let's add a check for s->xmit_pos.
    upstream-commit-id:
    7b50d00911ddd6d56a766ac5671e47304c20a21b (CVE-2015-3209)

  - gnttab: add missing version check to
    GNTTABOP_swap_grant_ref handling ... avoiding NULL
    derefs when the version to use wasn't set yet (via
    GNTTABOP_setup_table or GNTTABOP_set_version). This is
    XSA-134. (CVE-2015-4163)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2015-June/000316.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected xen / xen-tools packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:xen-tools");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2015/06/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/06/12");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");
  script_family(english:"OracleVM Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/OracleVM/release", "Host/OracleVM/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/OracleVM/release");
if (isnull(release) || "OVS" >!< release) audit(AUDIT_OS_NOT, "OracleVM");
if (! ereg(pattern:"^OVS" + "3\.3" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 3.3", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);
if ("x86_64" >!< cpu) audit(AUDIT_ARCH_NOT, "x86_64", cpu);

flag = 0;
if (rpm_check(release:"OVS3.3", reference:"xen-4.3.0-55.el6.22.52")) flag++;
if (rpm_check(release:"OVS3.3", reference:"xen-tools-4.3.0-55.el6.22.52")) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:rpm_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = pkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "xen / xen-tools");
}
