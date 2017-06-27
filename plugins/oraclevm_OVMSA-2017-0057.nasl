#
# (C) Tenable Network Security, Inc.
#
# The package checks in this plugin were extracted from OracleVM
# Security Advisory OVMSA-2017-0057.
#

include("compat.inc");

if (description)
{
  script_id(99163);
  script_version("$Revision: 3.4 $");
  script_cvs_date("$Date: 2017/04/11 16:42:26 $");

  script_cve_id("CVE-2013-0343", "CVE-2013-1059", "CVE-2013-2140", "CVE-2013-2147", "CVE-2013-2148", "CVE-2013-2164", "CVE-2013-2234", "CVE-2013-2237", "CVE-2013-2850", "CVE-2013-2851", "CVE-2013-2852", "CVE-2013-2888", "CVE-2013-2889", "CVE-2013-2892", "CVE-2013-2893", "CVE-2013-2895", "CVE-2013-2896", "CVE-2013-2897", "CVE-2013-2898", "CVE-2013-2899", "CVE-2013-2929", "CVE-2013-2930", "CVE-2013-4162", "CVE-2013-4163", "CVE-2013-4299", "CVE-2013-4312", "CVE-2013-4345", "CVE-2013-4348", "CVE-2013-4350", "CVE-2013-4470", "CVE-2013-4579", "CVE-2013-4587", "CVE-2013-4592", "CVE-2013-6367", "CVE-2013-6368", "CVE-2013-6376", "CVE-2013-6383", "CVE-2013-6885", "CVE-2013-7263", "CVE-2013-7265", "CVE-2013-7266", "CVE-2013-7421", "CVE-2013-7446", "CVE-2014-0038", "CVE-2014-0049", "CVE-2014-0055", "CVE-2014-0069", "CVE-2014-0077", "CVE-2014-0101", "CVE-2014-0181", "CVE-2014-0196", "CVE-2014-1690", "CVE-2014-1737", "CVE-2014-1738", "CVE-2014-1739", "CVE-2014-2309", "CVE-2014-2523", "CVE-2014-2851", "CVE-2014-3144", "CVE-2014-3145", "CVE-2014-3153", "CVE-2014-3181", "CVE-2014-3182", "CVE-2014-3184", "CVE-2014-3185", "CVE-2014-3186", "CVE-2014-3215", "CVE-2014-3535", "CVE-2014-3601", "CVE-2014-3610", "CVE-2014-3611", "CVE-2014-3645", "CVE-2014-3646", "CVE-2014-3673", "CVE-2014-3687", "CVE-2014-3688", "CVE-2014-4014", "CVE-2014-4027", "CVE-2014-4171", "CVE-2014-4652", "CVE-2014-4653", "CVE-2014-4654", "CVE-2014-4655", "CVE-2014-4656", "CVE-2014-4667", "CVE-2014-4699", "CVE-2014-4943", "CVE-2014-5471", "CVE-2014-5472", "CVE-2014-6410", "CVE-2014-7822", "CVE-2014-7826", "CVE-2014-7970", "CVE-2014-7975", "CVE-2014-8133", "CVE-2014-8134", "CVE-2014-8159", "CVE-2014-8160", "CVE-2014-8171", "CVE-2014-8173", "CVE-2014-8884", "CVE-2014-8989", "CVE-2014-9090", "CVE-2014-9322", "CVE-2014-9529", "CVE-2014-9585", "CVE-2014-9644", "CVE-2015-0239", "CVE-2015-1333", "CVE-2015-1421", "CVE-2015-1593", "CVE-2015-1805", "CVE-2015-2150", "CVE-2015-2830", "CVE-2015-2922", "CVE-2015-3212", "CVE-2015-3339", "CVE-2015-3636", "CVE-2015-4700", "CVE-2015-5156", "CVE-2015-5157", "CVE-2015-5283", "CVE-2015-5307", "CVE-2015-5364", "CVE-2015-5366", "CVE-2015-5697", "CVE-2015-5707", "CVE-2015-6937", "CVE-2015-7613", "CVE-2015-7872", "CVE-2015-8104", "CVE-2015-8215", "CVE-2015-8374", "CVE-2015-8543", "CVE-2015-8569", "CVE-2015-8767", "CVE-2015-8956", "CVE-2016-0728", "CVE-2016-0758", "CVE-2016-0774", "CVE-2016-10088", "CVE-2016-10142", "CVE-2016-1583", "CVE-2016-2053", "CVE-2016-2117", "CVE-2016-3070", "CVE-2016-3134", "CVE-2016-3140", "CVE-2016-3157", "CVE-2016-3672", "CVE-2016-3699", "CVE-2016-4470", "CVE-2016-4482", "CVE-2016-4485", "CVE-2016-4565", "CVE-2016-4569", "CVE-2016-4578", "CVE-2016-4580", "CVE-2016-4997", "CVE-2016-4998", "CVE-2016-5195", "CVE-2016-5696", "CVE-2016-5829", "CVE-2016-6136", "CVE-2016-6327", "CVE-2016-6480", "CVE-2016-6828", "CVE-2016-7042", "CVE-2016-7117", "CVE-2016-7425", "CVE-2016-8399", "CVE-2016-8633", "CVE-2016-8645", "CVE-2016-8646", "CVE-2016-8650", "CVE-2016-8655", "CVE-2016-9178", "CVE-2016-9555", "CVE-2016-9588", "CVE-2016-9644", "CVE-2016-9793", "CVE-2016-9794", "CVE-2017-2636", "CVE-2017-5970", "CVE-2017-6074", "CVE-2017-6345", "CVE-2017-7187");
  script_bugtraq_id(58795, 60243, 60280, 60341, 60375, 60409, 60410, 60414, 60874, 60922, 60953, 61411, 61412, 62042, 62043, 62044, 62045, 62046, 62048, 62049, 62050, 62056, 62405, 62740, 63183, 63359, 63536, 63743, 63790, 63888, 63983, 64111, 64270, 64291, 64318, 64319, 64328, 64677, 64686, 64743, 65180, 65255, 65588, 65909, 65943, 66095, 66279, 66441, 66678, 66779, 67034, 67199, 67282, 67300, 67302, 67309, 67321, 67341, 67906, 67985, 67988, 68048, 68157, 68159, 68162, 68163, 68164, 68170, 68224, 68411, 68683, 68768, 69396, 69428, 69489, 69721, 69763, 69768, 69770, 69779, 69781, 69799, 70314, 70319, 70742, 70743, 70745, 70746, 70766, 70768, 70883, 70971, 71097, 71154, 71250, 71367, 71650, 71684, 71685, 71880, 71990, 72061, 72320, 72322, 72347, 72356, 72607, 72842, 73014, 73060, 73133, 73699, 74243, 74293, 74315, 74450, 74951, 75356, 75510, 76005);
  script_osvdb_id(94853, 96766, 96768, 96770, 96774, 99324, 100422, 100986, 100987, 102749, 104003, 106174, 106646, 106969, 107752, 107819, 108001, 108026, 108287, 108386, 108389, 108390, 108451, 108473, 108754, 109277, 110240, 110564, 110565, 110567, 110568, 110569, 110570, 110571, 110572, 110732, 111297, 111406, 111409, 111430, 113014, 113724, 113726, 113727, 113731, 113823, 114370, 114957, 114958, 115163, 115870, 115919, 115920, 116762, 116910, 117131, 117716, 117749, 117762, 117810, 118498, 119233, 119409, 119630, 120282, 120284, 121104, 121170, 121578, 122968, 123637, 123996, 124240, 125208, 125430, 125431, 125710, 125846, 127518, 127759, 128012, 128379, 129330, 130089, 130090, 130525, 130832, 131685, 131952, 132811, 133126, 133379, 133550, 135678, 135876, 135947, 135961, 136761, 137963, 138086, 138176, 138215, 138383, 138431, 138444, 139987, 140046, 140493, 140494, 140558, 140971, 141441, 142610, 142992, 143247, 144411, 144731, 145048, 145102, 145585, 146061, 146703, 146778, 147168, 147301, 147698, 147818, 148164, 148195, 148388, 148409, 148443, 148861, 150179, 151927, 152302, 152728, 152729, 153186, 154043);
  script_xref(name:"IAVA", value:"2016-A-0306");

  script_name(english:"OracleVM 3.3 : Unbreakable / etc (OVMSA-2017-0057) (Dirty COW)");
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
OVMSA-2017-0057 for details."
  );
  # https://oss.oracle.com/pipermail/oraclevm-errata/2017-April/000675.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?bc2355e2"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected kernel-uek / kernel-uek-firmware packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_cvss3_base_vector("CVSS:3.0/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H");
  script_set_cvss3_temporal_vector("CVSS:3.0/E:P/RL:O/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Linux Kernel 4.6.3 Netfilter Privilege Escalation');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:vm:kernel-uek-firmware");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:vm_server:3.3");

  script_set_attribute(attribute:"patch_publication_date", value:"2017/04/01");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2017/04/03");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2017 Tenable Network Security, Inc.");
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
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-3.8.13-118.17.4.el6uek")) flag++;
if (rpm_check(release:"OVS3.3", reference:"kernel-uek-firmware-3.8.13-118.17.4.el6uek")) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "kernel-uek / kernel-uek-firmware");
}
