#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2013-0039.
#

include("compat.inc");

if (description)
{
  script_id(79507);
  script_version("$Revision: 1.18 $");
  script_cvs_date("$Date: 2017/04/03 14:49:09 $");

  script_cve_id("CVE-2006-6304", "CVE-2007-4567", "CVE-2009-0745", "CVE-2009-0746", "CVE-2009-0747", "CVE-2009-0748", "CVE-2009-1388", "CVE-2009-1389", "CVE-2009-1895", "CVE-2009-2406", "CVE-2009-2407", "CVE-2009-2692", "CVE-2009-2847", "CVE-2009-2848", "CVE-2009-2908", "CVE-2009-3080", "CVE-2009-3286", "CVE-2009-3547", "CVE-2009-3612", "CVE-2009-3620", "CVE-2009-3621", "CVE-2009-3726", "CVE-2009-4020", "CVE-2009-4021", "CVE-2009-4067", "CVE-2009-4138", "CVE-2009-4141", "CVE-2009-4307", "CVE-2009-4308", "CVE-2009-4536", "CVE-2009-4537", "CVE-2009-4538", "CVE-2010-0007", "CVE-2010-0415", "CVE-2010-0437", "CVE-2010-0622", "CVE-2010-0727", "CVE-2010-1083", "CVE-2010-1084", "CVE-2010-1086", "CVE-2010-1087", "CVE-2010-1088", "CVE-2010-1173", "CVE-2010-1188", "CVE-2010-1436", "CVE-2010-1437", "CVE-2010-1641", "CVE-2010-2226", "CVE-2010-2240", "CVE-2010-2248", "CVE-2010-2521", "CVE-2010-2798", "CVE-2010-2942", "CVE-2010-2963", "CVE-2010-3067", "CVE-2010-3078", "CVE-2010-3086", "CVE-2010-3296", "CVE-2010-3432", "CVE-2010-3442", "CVE-2010-3477", "CVE-2010-3858", "CVE-2010-3859", "CVE-2010-3876", "CVE-2010-3877", "CVE-2010-4073", "CVE-2010-4080", "CVE-2010-4081", "CVE-2010-4083", "CVE-2010-4157", "CVE-2010-4158", "CVE-2010-4242", "CVE-2010-4248", "CVE-2010-4249", "CVE-2010-4258", "CVE-2010-4346", "CVE-2010-4649", "CVE-2010-4655", "CVE-2011-0521", "CVE-2011-0726", "CVE-2011-1010", "CVE-2011-1020", "CVE-2011-1044", "CVE-2011-1078", "CVE-2011-1079", "CVE-2011-1080", "CVE-2011-1083", "CVE-2011-1090", "CVE-2011-1093", "CVE-2011-1160", "CVE-2011-1162", "CVE-2011-1163", "CVE-2011-1182", "CVE-2011-1573", "CVE-2011-1577", "CVE-2011-1585", "CVE-2011-1745", "CVE-2011-1746", "CVE-2011-1776", "CVE-2011-1833", "CVE-2011-2022", "CVE-2011-2203", "CVE-2011-2213", "CVE-2011-2482", "CVE-2011-2484", "CVE-2011-2491", "CVE-2011-2496", "CVE-2011-2525", "CVE-2011-3191", "CVE-2011-3637", "CVE-2011-3638", "CVE-2011-4077", "CVE-2011-4086", "CVE-2011-4110", "CVE-2011-4127", "CVE-2011-4324", "CVE-2011-4330", "CVE-2011-4348", "CVE-2012-1583", "CVE-2012-2136");
  script_bugtraq_id(35281, 35647, 35850, 35851, 35930, 36038, 36472, 36639, 36723, 36824, 36827, 36901, 36936, 37068, 37069, 37339, 37519, 37521, 37523, 37762, 37806, 38144, 38165, 38185, 38479, 38898, 39016, 39042, 39044, 39101, 39569, 39715, 39719, 39794, 40356, 40920, 42124, 42242, 42249, 42505, 42529, 43022, 43221, 43353, 43480, 43787, 43809, 44242, 44301, 44354, 44630, 44648, 44754, 44758, 45014, 45028, 45037, 45058, 45063, 45073, 45159, 45323, 45972, 45986, 46073, 46488, 46492, 46567, 46616, 46630, 46766, 46793, 46866, 46878, 47003, 47308, 47321, 47343, 47381, 47534, 47535, 47791, 47796, 47843, 48236, 48333, 48383, 48641, 48687, 49108, 49141, 49295, 49373, 50322, 50370, 50750, 50755, 50764, 50798, 51176, 51361, 51363, 51945, 53139, 53721);
  script_osvdb_id(52364, 55807, 56992, 59654, 62168, 71271);

  script_name(english:"OracleVM 2.2 : kernel (OVMSA-2013-0039)");
  script_summary(english:"Checks the RPM output for the updated packages.");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote OracleVM host is missing one or more security updates."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote OracleVM system is missing necessary patches to address
critical security updates : please see Oracle VM Security Advisory
OVMSA-2013-0039 for details."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://oss.oracle.com/pipermail/oraclevm-errata/2013-May/000153.html"
  );
  script_set_attribute(attribute:"solution", value:"Update the affected packages.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel Sendpage Local Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(16, 20, 119, 189, 200, 264, 362, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-PAE");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-PAE-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-ovs-devel");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:2.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/11/26");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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
if (! ereg(pattern:"^OVS" + "2\.2" + "(\.[0-9]|$)", string:release)) audit(AUDIT_OS_NOT, "OracleVM 2.2", "OracleVM " + release);
if (!get_kb_item("Host/OracleVM/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

cpu = get_kb_item("Host/cpu");
if (isnull(cpu)) audit(AUDIT_UNKNOWN_ARCH);
if ("x86_64" >!< cpu && cpu !~ "^i[3-6]86$") audit(AUDIT_LOCAL_CHECKS_NOT_IMPLEMENTED, "OracleVM", cpu);

flag = 0;
if (rpm_check(release:"OVS2.2", reference:"kernel-2.6.18-128.2.1.5.10.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-PAE-2.6.18-128.2.1.5.10.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-PAE-devel-2.6.18-128.2.1.5.10.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-devel-2.6.18-128.2.1.5.10.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-ovs-2.6.18-128.2.1.5.10.el5")) flag++;
if (rpm_check(release:"OVS2.2", reference:"kernel-ovs-devel-2.6.18-128.2.1.5.10.el5")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel / kernel-PAE / kernel-PAE-devel / kernel-devel / kernel-ovs / etc");
}
