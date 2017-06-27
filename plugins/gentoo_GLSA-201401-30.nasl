#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201401-30.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(72139);
  script_version("$Revision: 1.14 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2011-3563", "CVE-2011-5035", "CVE-2012-0497", "CVE-2012-0498", "CVE-2012-0499", "CVE-2012-0500", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0504", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0507", "CVE-2012-0547", "CVE-2012-1531", "CVE-2012-1532", "CVE-2012-1533", "CVE-2012-1541", "CVE-2012-1682", "CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1721", "CVE-2012-1722", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725", "CVE-2012-1726", "CVE-2012-3136", "CVE-2012-3143", "CVE-2012-3159", "CVE-2012-3174", "CVE-2012-3213", "CVE-2012-3216", "CVE-2012-3342", "CVE-2012-4416", "CVE-2012-4681", "CVE-2012-5067", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5074", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5083", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5088", "CVE-2012-5089", "CVE-2013-0169", "CVE-2013-0351", "CVE-2013-0401", "CVE-2013-0402", "CVE-2013-0409", "CVE-2013-0419", "CVE-2013-0422", "CVE-2013-0423", "CVE-2013-0430", "CVE-2013-0437", "CVE-2013-0438", "CVE-2013-0445", "CVE-2013-0446", "CVE-2013-0448", "CVE-2013-0449", "CVE-2013-0809", "CVE-2013-1473", "CVE-2013-1479", "CVE-2013-1481", "CVE-2013-1484", "CVE-2013-1485", "CVE-2013-1486", "CVE-2013-1487", "CVE-2013-1488", "CVE-2013-1491", "CVE-2013-1493", "CVE-2013-1500", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1540", "CVE-2013-1557", "CVE-2013-1558", "CVE-2013-1561", "CVE-2013-1563", "CVE-2013-1564", "CVE-2013-1569", "CVE-2013-1571", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2394", "CVE-2013-2400", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2414", "CVE-2013-2415", "CVE-2013-2416", "CVE-2013-2417", "CVE-2013-2418", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2425", "CVE-2013-2426", "CVE-2013-2427", "CVE-2013-2428", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2432", "CVE-2013-2433", "CVE-2013-2434", "CVE-2013-2435", "CVE-2013-2436", "CVE-2013-2437", "CVE-2013-2438", "CVE-2013-2439", "CVE-2013-2440", "CVE-2013-2442", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2462", "CVE-2013-2463", "CVE-2013-2464", "CVE-2013-2465", "CVE-2013-2466", "CVE-2013-2467", "CVE-2013-2468", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3743", "CVE-2013-3744", "CVE-2013-3829", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5775", "CVE-2013-5776", "CVE-2013-5777", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5787", "CVE-2013-5788", "CVE-2013-5789", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5801", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5805", "CVE-2013-5806", "CVE-2013-5809", "CVE-2013-5810", "CVE-2013-5812", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5818", "CVE-2013-5819", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5824", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5831", "CVE-2013-5832", "CVE-2013-5838", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5843", "CVE-2013-5844", "CVE-2013-5846", "CVE-2013-5848", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851", "CVE-2013-5852", "CVE-2013-5854", "CVE-2013-5870", "CVE-2013-5878", "CVE-2013-5887", "CVE-2013-5888", "CVE-2013-5889", "CVE-2013-5893", "CVE-2013-5895", "CVE-2013-5896", "CVE-2013-5898", "CVE-2013-5899", "CVE-2013-5902", "CVE-2013-5904", "CVE-2013-5905", "CVE-2013-5906", "CVE-2013-5907", "CVE-2013-5910", "CVE-2014-0368", "CVE-2014-0373", "CVE-2014-0375", "CVE-2014-0376", "CVE-2014-0382", "CVE-2014-0385", "CVE-2014-0387", "CVE-2014-0403", "CVE-2014-0408", "CVE-2014-0410", "CVE-2014-0411", "CVE-2014-0415", "CVE-2014-0416", "CVE-2014-0417", "CVE-2014-0418", "CVE-2014-0422", "CVE-2014-0423", "CVE-2014-0424", "CVE-2014-0428");
  script_bugtraq_id(51194, 52009, 52011, 52012, 52013, 52014, 52015, 52016, 52017, 52018, 52019, 52020, 52161, 53946, 53947, 53948, 53949, 53950, 53951, 53952, 53953, 53954, 53958, 53959, 53960, 55213, 55336, 55337, 55339, 55501, 56025, 56033, 56039, 56043, 56046, 56051, 56054, 56055, 56056, 56057, 56058, 56059, 56061, 56063, 56065, 56067, 56070, 56071, 56072, 56075, 56076, 56079, 56080, 56081, 56082, 56083, 57246, 57312, 57681, 57689, 57697, 57699, 57700, 57704, 57706, 57708, 57714, 57716, 57717, 57718, 57720, 57722, 57723, 57728, 57731, 57778, 58027, 58028, 58029, 58031, 58238, 58296, 58397, 58493, 58504, 58507, 59088, 59089, 59124, 59128, 59131, 59137, 59141, 59145, 59149, 59153, 59154, 59159, 59162, 59165, 59166, 59167, 59170, 59172, 59175, 59178, 59179, 59184, 59185, 59187, 59190, 59191, 59194, 59195, 59203, 59206, 59208, 59212, 59213, 59219, 59220, 59228, 59234, 59243, 60617, 60618, 60619, 60620, 60621, 60622, 60623, 60624, 60625, 60626, 60627, 60629, 60630, 60631, 60632, 60633, 60634, 60635, 60636, 60637, 60638, 60639, 60640, 60641, 60643, 60644, 60645, 60646, 60647, 60649, 60650, 60651, 60652, 60653, 60654, 60655, 60656, 60657, 60658, 60659, 63079, 63082, 63089, 63095, 63098, 63101, 63102, 63103, 63106, 63110, 63111, 63112, 63115, 63118, 63120, 63121, 63122, 63124, 63126, 63127, 63128, 63129, 63130, 63131, 63132, 63133, 63134, 63135, 63136, 63137, 63139, 63140, 63141, 63142, 63143, 63144, 63145, 63146, 63147, 63148, 63149, 63150, 63151, 63152, 63153, 63154, 63155, 63156, 63157, 63158, 64863, 64875, 64882, 64890, 64894, 64899, 64901, 64903, 64906, 64907, 64910, 64912, 64914, 64915, 64916, 64917, 64918, 64919, 64920, 64921, 64922, 64923, 64925, 64926, 64927, 64928, 64929, 64930, 64931, 64932, 64933, 64934, 64935, 64936, 64937);
  script_xref(name:"GLSA", value:"201401-30");

  script_name(english:"GLSA-201401-30 : Oracle JRE/JDK: Multiple vulnerabilities");
  script_summary(english:"Checks for updated package(s) in /var/db/pkg");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Gentoo host is missing one or more security-related
patches."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote host is affected by the vulnerability described in GLSA-201401-30
(Oracle JRE/JDK: Multiple vulnerabilities)

    Multiple vulnerabilities have been reported in the Oracle Java
      implementation. Please review the CVE identifiers referenced below for
      details.
  
Impact :

    An unauthenticated, remote attacker could exploit these vulnerabilities
      to execute arbitrary code.
      Furthermore, a local or remote attacker could exploit these
      vulnerabilities to cause unspecified impact, possibly including remote
      execution of arbitrary code.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201401-30"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Oracle JDK 1.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jdk-bin-1.7.0.51'
    All Oracle JRE 1.7 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=dev-java/oracle-jre-bin-1.7.0.51'
    All users of the precompiled 32-bit Oracle JRE should upgrade to the
      latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=app-emulation/emul-linux-x86-java-1.7.0.51'
    All Sun Microsystems JDK/JRE 1.6 users are suggested to upgrade to one
      of the newer Oracle packages like dev-java/oracle-jdk-bin or
      dev-java/oracle-jre-bin or choose another alternative we provide; eg. the
      IBM JDK/JRE or the open source IcedTea.
    NOTE: As Oracle has revoked the DLJ license for its Java implementation,
      the packages can no longer be updated automatically."
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:emul-linux-x86-java");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jdk-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:oracle-jre-bin");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jdk");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:sun-jre-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/01/27");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/01/27");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2016 Tenable Network Security, Inc.");
  script_family(english:"Gentoo Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Gentoo/release", "Host/Gentoo/qpkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("qpkg.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
if (!get_kb_item("Host/Gentoo/release")) audit(AUDIT_OS_NOT, "Gentoo");
if (!get_kb_item("Host/Gentoo/qpkg-list")) audit(AUDIT_PACKAGE_LIST_MISSING);


flag = 0;

if (qpkg_check(package:"dev-java/sun-jre-bin", unaffected:make_list(), vulnerable:make_list("le 1.6.0.45"))) flag++;
if (qpkg_check(package:"app-emulation/emul-linux-x86-java", unaffected:make_list("ge 1.7.0.51"), vulnerable:make_list("lt 1.7.0.51"))) flag++;
if (qpkg_check(package:"dev-java/sun-jdk", unaffected:make_list(), vulnerable:make_list("le 1.6.0.45"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jre-bin", unaffected:make_list("ge 1.7.0.51"), vulnerable:make_list("lt 1.7.0.51"))) flag++;
if (qpkg_check(package:"dev-java/oracle-jdk-bin", unaffected:make_list("ge 1.7.0.51"), vulnerable:make_list("lt 1.7.0.51"))) flag++;

if (flag)
{
  if (report_verbosity > 0) security_hole(port:0, extra:qpkg_report_get());
  else security_hole(0);
  exit(0);
}
else
{
  tested = qpkg_tests_get();
  if (tested) audit(AUDIT_PACKAGE_NOT_AFFECTED, tested);
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Oracle JRE/JDK");
}
