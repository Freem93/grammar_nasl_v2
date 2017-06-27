#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Amazon Linux AMI Security Advisory ALAS-2016-718.
#

include("compat.inc");

if (description)
{
  script_id(91858);
  script_version("$Revision: 2.7 $");
  script_cvs_date("$Date: 2017/01/20 15:01:12 $");

  script_cve_id("CVE-2016-4951", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-9806");
  script_xref(name:"ALAS", value:"2016-718");

  script_name(english:"Amazon Linux AMI : kernel (ALAS-2016-718)");
  script_summary(english:"Checks rpm output for the updated packages");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote Amazon Linux AMI host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"A flaw was discovered in processing setsockopt for 32 bit processes on
64 bit systems. This flaw will allow attackers to alter arbitary
kernel memory when unloading a kernel module. This action is usually
restricted to root-priveledged users but can also be leveraged if the
kernel is compiled with CONFIG_USER_NS and CONFIG_NET_NS.
(CVE-2016-4997)

An out-of-bounds heap memory access leading to a Denial of Service,
heap disclosure, or further impact was found in setsockopt(). The
function call is normally restricted to root, however some processes
with cap_sys_admin may also be able to trigger this flaw in privileged
container environments. (CVE-2016-4998)

A vulnerability was found in the Linux kernel. The pointer to the
netlink socket attribute is not checked, which could cause a NULL
pointer dereference when parsing the nested attributes in function
tipc_nl_publ_dump().

This allows local users to cause a DoS. (CVE-2016-4951)

A double free vulnerability was found in netlink_dump, which could
cause a denial of service or possibly other unspecified impact.
(CVE-2016-9806)

(Updated on 2016-07-14: CVE-2016-4998 and CVE-2016-4951 were fixed in
this version, but was not previously listed in this errata.)

(Updated on 2017-01-19: CVE-2016-9806 was fixed in this release but
was previously not part of this errata.)"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://alas.aws.amazon.com/ALAS-2016-718.html"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Run 'yum update kernel' to update your system."
  );
  script_set_cvss_base_vector("CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:H");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-i686");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-debuginfo-common-x86_64");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-doc");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-headers");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-debuginfo");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:kernel-tools-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:amazon:linux:perf-debuginfo");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:amazon:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2016/06/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2016/06/28");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2016-2017 Tenable Network Security, Inc.");
  script_family(english:"Amazon Linux Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/AmazonLinux/release", "Host/AmazonLinux/rpm-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");


if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/AmazonLinux/release")) audit(AUDIT_OS_NOT, "Amazon Linux AMI");
if (!get_kb_item("Host/AmazonLinux/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;
if (rpm_check(release:"ALA", reference:"kernel-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-debuginfo-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"i686", reference:"kernel-debuginfo-common-i686-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", cpu:"x86_64", reference:"kernel-debuginfo-common-x86_64-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-devel-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-doc-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-headers-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-debuginfo-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"kernel-tools-devel-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-4.4.14-24.50.amzn1")) flag++;
if (rpm_check(release:"ALA", reference:"perf-debuginfo-4.4.14-24.50.amzn1")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-debuginfo / kernel-debuginfo-common-i686 / etc");
}
