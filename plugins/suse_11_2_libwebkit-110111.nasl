#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from openSUSE Security Update libwebkit-3787.
#
# The text description of this plugin is (C) SUSE LLC.
#

include("compat.inc");

if (description)
{
  script_id(53764);
  script_version("$Revision: 1.5 $");
  script_cvs_date("$Date: 2016/12/21 20:21:19 $");

  script_cve_id("CVE-2009-0945", "CVE-2009-1681", "CVE-2009-1684", "CVE-2009-1685", "CVE-2009-1686", "CVE-2009-1687", "CVE-2009-1688", "CVE-2009-1689", "CVE-2009-1690", "CVE-2009-1691", "CVE-2009-1692", "CVE-2009-1693", "CVE-2009-1694", "CVE-2009-1695", "CVE-2009-1696", "CVE-2009-1697", "CVE-2009-1698", "CVE-2009-1699", "CVE-2009-1700", "CVE-2009-1701", "CVE-2009-1702", "CVE-2009-1703", "CVE-2009-1709", "CVE-2009-1710", "CVE-2009-1711", "CVE-2009-1712", "CVE-2009-1713", "CVE-2009-1714", "CVE-2009-1715", "CVE-2009-1718", "CVE-2009-1724", "CVE-2009-1725", "CVE-2009-2195", "CVE-2009-2199", "CVE-2009-2200", "CVE-2009-2419", "CVE-2009-2797", "CVE-2009-2816", "CVE-2009-2841", "CVE-2009-3272", "CVE-2009-3384", "CVE-2009-3933", "CVE-2009-3934", "CVE-2010-0046", "CVE-2010-0047", "CVE-2010-0048", "CVE-2010-0049", "CVE-2010-0050", "CVE-2010-0051", "CVE-2010-0052", "CVE-2010-0053", "CVE-2010-0054", "CVE-2010-0315", "CVE-2010-0647", "CVE-2010-0650", "CVE-2010-0651", "CVE-2010-0656", "CVE-2010-0659", "CVE-2010-0661", "CVE-2010-1029", "CVE-2010-1126", "CVE-2010-1233", "CVE-2010-1236", "CVE-2010-1386", "CVE-2010-1387", "CVE-2010-1388", "CVE-2010-1389", "CVE-2010-1390", "CVE-2010-1391", "CVE-2010-1392", "CVE-2010-1393", "CVE-2010-1394", "CVE-2010-1395", "CVE-2010-1396", "CVE-2010-1397", "CVE-2010-1398", "CVE-2010-1399", "CVE-2010-1400", "CVE-2010-1401", "CVE-2010-1402", "CVE-2010-1403", "CVE-2010-1404", "CVE-2010-1405", "CVE-2010-1406", "CVE-2010-1407", "CVE-2010-1408", "CVE-2010-1409", "CVE-2010-1410", "CVE-2010-1412", "CVE-2010-1413", "CVE-2010-1414", "CVE-2010-1415", "CVE-2010-1416", "CVE-2010-1417", "CVE-2010-1418", "CVE-2010-1419", "CVE-2010-1421", "CVE-2010-1422", "CVE-2010-1729", "CVE-2010-1749", "CVE-2010-1757", "CVE-2010-1758", "CVE-2010-1759", "CVE-2010-1760", "CVE-2010-1761", "CVE-2010-1762", "CVE-2010-1763", "CVE-2010-1764", "CVE-2010-1766", "CVE-2010-1767", "CVE-2010-1769", "CVE-2010-1770", "CVE-2010-1771", "CVE-2010-1772", "CVE-2010-1773", "CVE-2010-1774", "CVE-2010-1780", "CVE-2010-1781", "CVE-2010-1782", "CVE-2010-1783", "CVE-2010-1784", "CVE-2010-1785", "CVE-2010-1786", "CVE-2010-1787", "CVE-2010-1788", "CVE-2010-1789", "CVE-2010-1790", "CVE-2010-1791", "CVE-2010-1792", "CVE-2010-1793", "CVE-2010-1807", "CVE-2010-1812", "CVE-2010-1813", "CVE-2010-1814", "CVE-2010-1815", "CVE-2010-1822", "CVE-2010-1823", "CVE-2010-1824", "CVE-2010-1825", "CVE-2010-2264", "CVE-2010-2295", "CVE-2010-2297", "CVE-2010-2300", "CVE-2010-2301", "CVE-2010-2302", "CVE-2010-2441", "CVE-2010-3116", "CVE-2010-3257", "CVE-2010-3259", "CVE-2010-3312", "CVE-2010-3803", "CVE-2010-3804", "CVE-2010-3805", "CVE-2010-3808", "CVE-2010-3809", "CVE-2010-3810", "CVE-2010-3811", "CVE-2010-3812", "CVE-2010-3813", "CVE-2010-3816", "CVE-2010-3817", "CVE-2010-3818", "CVE-2010-3819", "CVE-2010-3820", "CVE-2010-3821", "CVE-2010-3822", "CVE-2010-3823", "CVE-2010-3824", "CVE-2010-3826", "CVE-2010-3829", "CVE-2010-3900");

  script_name(english:"openSUSE Security Update : libwebkit (openSUSE-SU-2011:0024-1)");
  script_summary(english:"Check for the libwebkit-3787 patch");

  script_set_attribute(
    attribute:"synopsis", 
    value:"The remote openSUSE host is missing a security update."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"Various bugs in webkit have been fixed. The CVE id's are :

CVE-2009-0945, CVE-2009-1681, CVE-2009-1684, CVE-2009-1685,
CVE-2009-1686, CVE-2009-1687, CVE-2009-1688, CVE-2009-1689,
CVE-2009-1691, CVE-2009-1690, CVE-2009-1692, CVE-2009-1693,
CVE-2009-1694, CVE-2009-1695, CVE-2009-1696, CVE-2009-1697,
CVE-2009-1698, CVE-2009-1699, CVE-2009-1700, CVE-2009-1701,
CVE-2009-1702, CVE-2009-1703, CVE-2009-1709, CVE-2009-1710,
CVE-2009-1711, CVE-2009-1712, CVE-2009-1713, CVE-2009-1714,
CVE-2009-1715, CVE-2009-1718, CVE-2009-1724, CVE-2009-1725,
CVE-2009-2195, CVE-2009-2199, CVE-2009-2200, CVE-2009-2419,
CVE-2009-2797, CVE-2009-2816, CVE-2009-2841, CVE-2009-3272,
CVE-2009-3384, CVE-2009-3933, CVE-2009-3934, CVE-2010-0046,
CVE-2010-0047, CVE-2010-0048, CVE-2010-0049, CVE-2010-0050,
CVE-2010-0052, CVE-2010-0053, CVE-2010-0054, CVE-2010-0315,
CVE-2010-0647, CVE-2010-0051, CVE-2010-0650, CVE-2010-0651,
CVE-2010-0656, CVE-2010-0659, CVE-2010-0661, CVE-2010-1029,
CVE-2010-1126, CVE-2010-1233, CVE-2010-1236, CVE-2010-1386,
CVE-2010-1387, CVE-2010-1388, CVE-2010-1389, CVE-2010-1390,
CVE-2010-1391, CVE-2010-1392, CVE-2010-1393, CVE-2010-1394,
CVE-2010-1395, CVE-2010-1396, CVE-2010-1397, CVE-2010-1398,
CVE-2010-1399, CVE-2010-1400, CVE-2010-1401, CVE-2010-1402,
CVE-2010-1403, CVE-2010-1404, CVE-2010-1405, CVE-2010-1406,
CVE-2010-1407, CVE-2010-1408, CVE-2010-1409, CVE-2010-1410,
CVE-2010-1412, CVE-2010-1413, CVE-2010-1414, CVE-2010-1415,
CVE-2010-1416, CVE-2010-1417, CVE-2010-1418, CVE-2010-1419,
CVE-2010-1421, CVE-2010-1422, CVE-2010-1729, CVE-2010-1749,
CVE-2010-1757, CVE-2010-1758, CVE-2010-1759, CVE-2010-1760,
CVE-2010-1761, CVE-2010-1762, CVE-2010-1763, CVE-2010-1764,
CVE-2010-1766, CVE-2010-1767, CVE-2010-1769, CVE-2010-1770,
CVE-2010-1771, CVE-2010-1772, CVE-2010-1773, CVE-2010-1774,
CVE-2010-1780, CVE-2010-1781, CVE-2010-1782, CVE-2010-1783,
CVE-2010-1784, CVE-2010-1785, CVE-2010-1786, CVE-2010-1787,
CVE-2010-1788, CVE-2010-1789, CVE-2010-1790, CVE-2010-1791,
CVE-2010-1792, CVE-2010-1793, CVE-2010-1807, CVE-2010-1812,
CVE-2010-1813, CVE-2010-1814, CVE-2010-1815, CVE-2010-1822,
CVE-2010-1823, CVE-2010-1824, CVE-2010-1825, CVE-2010-2264,
CVE-2010-2295, CVE-2010-2297, CVE-2010-2300, CVE-2010-2301,
CVE-2010-2302, CVE-2010-2441, CVE-2010-3116, CVE-2010-3257,
CVE-2010-3259, CVE-2010-3312, CVE-2010-3803, CVE-2010-3804,
CVE-2010-3805, CVE-2010-3808, CVE-2010-3809, CVE-2010-3810,
CVE-2010-3811, CVE-2010-3812, CVE-2010-3813, CVE-2010-3816,
CVE-2010-3817, CVE-2010-3818, CVE-2010-3819, CVE-2010-3820,
CVE-2010-3821, CVE-2010-3822, CVE-2010-3823, CVE-2010-3824,
CVE-2010-3826, CVE-2010-3829, CVE-2010-3900, CVE-2010-4040"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://lists.opensuse.org/opensuse-updates/2011-01/msg00013.html"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://bugzilla.novell.com/show_bug.cgi?id=601349"
  );
  script_set_attribute(
    attribute:"solution", 
    value:"Update the affected libwebkit packages."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(20, 79, 94, 119, 189, 200, 264, 310, 352, 399);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-1_0-2");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-devel");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:libwebkit-lang");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:novell:opensuse:webkit-jsc");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:novell:opensuse:11.2");

  script_set_attribute(attribute:"patch_publication_date", value:"2011/01/11");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/05/05");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_family(english:"SuSE Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/SuSE/release", "Host/SuSE/rpm-list", "Host/cpu");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("rpm.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/SuSE/release");
if (isnull(release) || release =~ "^(SLED|SLES)") audit(AUDIT_OS_NOT, "openSUSE");
if (release !~ "^(SUSE11\.2)$") audit(AUDIT_OS_RELEASE_NOT, "openSUSE", "11.2", release);
if (!get_kb_item("Host/SuSE/rpm-list")) audit(AUDIT_PACKAGE_LIST_MISSING);

ourarch = get_kb_item("Host/cpu");
if (!ourarch) audit(AUDIT_UNKNOWN_ARCH);
if (ourarch !~ "^(i586|i686|x86_64)$") audit(AUDIT_ARCH_NOT, "i586 / i686 / x86_64", ourarch);

flag = 0;

if ( rpm_check(release:"SUSE11.2", reference:"libwebkit-1_0-2-1.2.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libwebkit-devel-1.2.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"libwebkit-lang-1.2.6-0.5.1") ) flag++;
if ( rpm_check(release:"SUSE11.2", reference:"webkit-jsc-1.2.6-0.5.1") ) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "libwebkit-1_0-2 / libwebkit-devel / libwebkit-lang / webkit-jsc");
}
