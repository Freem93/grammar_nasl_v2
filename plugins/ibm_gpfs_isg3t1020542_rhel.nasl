#
# (C) Tenable Network Security, Inc.
#


include("compat.inc");


if (description)
{
  script_id(72506);
  script_version("$Revision: 1.3 $");
  script_cvs_date("$Date: 2014/03/21 21:52:40 $");

  script_cve_id("CVE-2014-0834");
  script_bugtraq_id(65297);
  script_osvdb_id(102765);

  script_name(english:"IBM General Parallel File System 3.4 < 3.4.0.27 / 3.5 < 3.5.0.16 DoS (RHEL)");
  script_summary(english:"Checks version of GPFS package");

  script_set_attribute(
    attribute:"synopsis",
    value:
"A clustered file system on the remote host is affected by a denial of
service vulnerability."
  );
  script_set_attribute(
    attribute:"description",
    value:
"A version of IBM General Parallel File System (GPFS) prior to 3.4.0.27
/ 3.5.0.16 is installed on the remote host.  It is, therefore, affected
by a denial of service vulnerability.  An authenticated, non-root
attacker can exploit this vulnerability by passing certain arguments to
'setuid' commands, potentially causing the GPFS daemon to crash."
  );
  # https://www-304.ibm.com/connections/blogs/PSIRT/entry/ibm_general_parallel_file_system_denial_of_service_vulnerability_cve_2014_0834?lang=en_us
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?5a45ae87");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=isg3T1020542");
  script_set_attribute(attribute:"solution", value:"Upgrade to GPFS 3.4.0.27 / 3.5.0.16 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:ND/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/02/14");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:general_parallel_file_system");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Red Hat Local Security Checks");

  script_copyright(english:"This script is Copyright (C) 2014 Tenable Network Security, Inc.");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/RedHat/release", "Host/RedHat/rpm-list");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/RedHat/release");
if (isnull(release) || "Red Hat" >!< release) audit(AUDIT_OS_NOT, "Red Hat");
if (!get_kb_item("Host/RedHat/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$" && "ppc" >!< cpu) audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "Red Hat", cpu);

flag = 0;
# 3.4 Checks.
fix1 = "gpfs.base-3.4.0-27";
if (rpm_check(release:"RHEL4", reference:fix1)) flag++;
else if (rpm_check(release:"RHEL5", reference:fix1)) flag++;
else if (rpm_check(release:"RHEL6", reference:fix1)) flag++;

# 3.5 Checks. Only run if 3.4 is not installed.
else if (!rpm_exists(rpm:"gpfs.base-3.4.0-", release:"RHEL"))
{
  fix2 = "gpfs.base-3.5.0-16";
  if (rpm_check(release:"RHEL5", reference:fix2)) flag++;
  else if (rpm_check(release:"RHEL6", reference:fix2)) flag++;
}

if (flag)
{
  if (report_verbosity > 0) security_warning(port:0, extra:rpm_report_get());
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_HOST_NOT, "affected");
