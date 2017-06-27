#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201406-32.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(76303);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/09/02 14:37:22 $");

  script_cve_id("CVE-2009-3555", "CVE-2010-2548", "CVE-2010-2783", "CVE-2010-3541", "CVE-2010-3548", "CVE-2010-3549", "CVE-2010-3551", "CVE-2010-3553", "CVE-2010-3554", "CVE-2010-3557", "CVE-2010-3561", "CVE-2010-3562", "CVE-2010-3564", "CVE-2010-3565", "CVE-2010-3566", "CVE-2010-3567", "CVE-2010-3568", "CVE-2010-3569", "CVE-2010-3573", "CVE-2010-3574", "CVE-2010-3860", "CVE-2010-4351", "CVE-2010-4448", "CVE-2010-4450", "CVE-2010-4465", "CVE-2010-4467", "CVE-2010-4469", "CVE-2010-4470", "CVE-2010-4471", "CVE-2010-4472", "CVE-2010-4476", "CVE-2011-0025", "CVE-2011-0706", "CVE-2011-0815", "CVE-2011-0822", "CVE-2011-0862", "CVE-2011-0864", "CVE-2011-0865", "CVE-2011-0868", "CVE-2011-0869", "CVE-2011-0870", "CVE-2011-0871", "CVE-2011-0872", "CVE-2011-3389", "CVE-2011-3521", "CVE-2011-3544", "CVE-2011-3547", "CVE-2011-3548", "CVE-2011-3551", "CVE-2011-3552", "CVE-2011-3553", "CVE-2011-3554", "CVE-2011-3556", "CVE-2011-3557", "CVE-2011-3558", "CVE-2011-3560", "CVE-2011-3563", "CVE-2011-3571", "CVE-2011-5035", "CVE-2012-0424", "CVE-2012-0497", "CVE-2012-0501", "CVE-2012-0502", "CVE-2012-0503", "CVE-2012-0505", "CVE-2012-0506", "CVE-2012-0547", "CVE-2012-1711", "CVE-2012-1713", "CVE-2012-1716", "CVE-2012-1717", "CVE-2012-1718", "CVE-2012-1719", "CVE-2012-1723", "CVE-2012-1724", "CVE-2012-1725", "CVE-2012-1726", "CVE-2012-3216", "CVE-2012-3422", "CVE-2012-3423", "CVE-2012-4416", "CVE-2012-4540", "CVE-2012-5068", "CVE-2012-5069", "CVE-2012-5070", "CVE-2012-5071", "CVE-2012-5072", "CVE-2012-5073", "CVE-2012-5074", "CVE-2012-5075", "CVE-2012-5076", "CVE-2012-5077", "CVE-2012-5079", "CVE-2012-5081", "CVE-2012-5084", "CVE-2012-5085", "CVE-2012-5086", "CVE-2012-5087", "CVE-2012-5089", "CVE-2013-0169", "CVE-2013-0401", "CVE-2013-0425", "CVE-2013-0426", "CVE-2013-0427", "CVE-2013-0428", "CVE-2013-0429", "CVE-2013-0431", "CVE-2013-0432", "CVE-2013-0433", "CVE-2013-0434", "CVE-2013-0435", "CVE-2013-0440", "CVE-2013-0441", "CVE-2013-0442", "CVE-2013-0443", "CVE-2013-0444", "CVE-2013-0450", "CVE-2013-0809", "CVE-2013-1475", "CVE-2013-1476", "CVE-2013-1478", "CVE-2013-1480", "CVE-2013-1484", "CVE-2013-1485", "CVE-2013-1486", "CVE-2013-1488", "CVE-2013-1493", "CVE-2013-1500", "CVE-2013-1518", "CVE-2013-1537", "CVE-2013-1557", "CVE-2013-1569", "CVE-2013-1571", "CVE-2013-2383", "CVE-2013-2384", "CVE-2013-2407", "CVE-2013-2412", "CVE-2013-2415", "CVE-2013-2417", "CVE-2013-2419", "CVE-2013-2420", "CVE-2013-2421", "CVE-2013-2422", "CVE-2013-2423", "CVE-2013-2424", "CVE-2013-2426", "CVE-2013-2429", "CVE-2013-2430", "CVE-2013-2431", "CVE-2013-2436", "CVE-2013-2443", "CVE-2013-2444", "CVE-2013-2445", "CVE-2013-2446", "CVE-2013-2447", "CVE-2013-2448", "CVE-2013-2449", "CVE-2013-2450", "CVE-2013-2451", "CVE-2013-2452", "CVE-2013-2453", "CVE-2013-2454", "CVE-2013-2455", "CVE-2013-2456", "CVE-2013-2457", "CVE-2013-2458", "CVE-2013-2459", "CVE-2013-2460", "CVE-2013-2461", "CVE-2013-2463", "CVE-2013-2465", "CVE-2013-2469", "CVE-2013-2470", "CVE-2013-2471", "CVE-2013-2472", "CVE-2013-2473", "CVE-2013-3829", "CVE-2013-4002", "CVE-2013-5772", "CVE-2013-5774", "CVE-2013-5778", "CVE-2013-5780", "CVE-2013-5782", "CVE-2013-5783", "CVE-2013-5784", "CVE-2013-5790", "CVE-2013-5797", "CVE-2013-5800", "CVE-2013-5802", "CVE-2013-5803", "CVE-2013-5804", "CVE-2013-5805", "CVE-2013-5806", "CVE-2013-5809", "CVE-2013-5814", "CVE-2013-5817", "CVE-2013-5820", "CVE-2013-5823", "CVE-2013-5825", "CVE-2013-5829", "CVE-2013-5830", "CVE-2013-5840", "CVE-2013-5842", "CVE-2013-5849", "CVE-2013-5850", "CVE-2013-5851", "CVE-2013-6629", "CVE-2013-6954", "CVE-2014-0429", "CVE-2014-0446", "CVE-2014-0451", "CVE-2014-0452", "CVE-2014-0453", "CVE-2014-0456", "CVE-2014-0457", "CVE-2014-0458", "CVE-2014-0459", "CVE-2014-0460", "CVE-2014-0461", "CVE-2014-1876", "CVE-2014-2397", "CVE-2014-2398", "CVE-2014-2403", "CVE-2014-2412", "CVE-2014-2414", "CVE-2014-2421", "CVE-2014-2423", "CVE-2014-2427");
  script_bugtraq_id(36935, 42476, 43963, 43979, 43985, 43988, 43992, 43994, 44009, 44011, 44012, 44013, 44014, 44016, 44017, 44027, 44028, 44032, 44035, 45114, 45894, 46091, 46110, 46387, 46395, 46397, 46398, 46399, 46400, 46404, 46406, 46439, 48137, 48139, 48140, 48141, 48142, 48143, 48146, 48147, 49388, 49778, 50211, 50215, 50216, 50218, 50224, 50231, 50234, 50236, 50242, 50243, 50246, 50248, 51194, 51467, 52009, 52011, 52012, 52013, 52014, 52017, 52018, 53946, 53947, 53948, 53949, 53950, 53951, 53952, 53954, 53958, 53960, 54762, 55339, 55501, 56039, 56043, 56054, 56056, 56058, 56059, 56061, 56063, 56065, 56067, 56071, 56075, 56076, 56079, 56080, 56081, 56083, 56434, 57686, 57687, 57691, 57692, 57694, 57696, 57701, 57702, 57703, 57709, 57710, 57711, 57712, 57713, 57719, 57724, 57726, 57727, 57729, 57730, 57778, 58027, 58028, 58029, 58238, 58296, 58504, 58507, 59131, 59141, 59153, 59159, 59162, 59165, 59166, 59167, 59170, 59179, 59184, 59187, 59190, 59194, 59206, 59212, 59213, 59228, 59243, 60617, 60618, 60619, 60620, 60622, 60623, 60625, 60627, 60629, 60632, 60633, 60634, 60635, 60638, 60639, 60640, 60641, 60644, 60645, 60646, 60647, 60650, 60651, 60652, 60653, 60655, 60656, 60657, 60658, 60659, 61310, 63082, 63089, 63095, 63098, 63101, 63102, 63103, 63106, 63110, 63111, 63112, 63115, 63118, 63120, 63121, 63122, 63128, 63133, 63134, 63135, 63137, 63142, 63143, 63146, 63148, 63149, 63150, 63153, 63154, 63676, 64493, 65568, 66856, 66866, 66873, 66877, 66879, 66881, 66883, 66887, 66891, 66893, 66894, 66902, 66903, 66909, 66910, 66914, 66916, 66918, 66920);
  script_osvdb_id(59968, 59969, 59970, 59971, 59972, 59973, 59974, 60366, 60521, 61234, 61718, 61784, 61785, 61929, 62064, 62135, 62210, 62273, 62536, 62877, 64040, 64499, 64725, 65202, 66315, 67029, 69032, 69561, 70055, 70620, 70965, 71951, 71961, 74335, 74829, 75622, 76500, 77832, 78114, 79229, 79230, 79232, 79233, 79235, 82874, 82877, 82882, 82884, 82886, 84363, 86350, 87249, 89190, 89613, 89758, 89760, 89761, 89762, 89763, 89767, 89769, 89771, 89772, 89785, 89786, 89792, 89795, 89796, 89798, 89800, 89801, 89802, 89804, 89806, 90353, 90354, 90355, 90597, 90737, 90837, 91206, 91472, 92335, 92336, 92337, 92339, 92342, 92343, 92344, 92346, 92347, 92348, 92358, 92359, 92360, 92361, 92362, 92363, 92364, 92365, 92366, 94335, 94336, 94337, 94339, 94340, 94341, 94347, 94348, 94350, 94352, 94353, 94355, 94356, 94357, 94358, 94362, 94363, 94364, 94365, 94366, 94367, 94368, 94369, 94370, 94372, 94373, 94374, 95418, 98524, 98525, 98526, 98531, 98532, 98535, 98537, 98538, 98544, 98546, 98548, 98549, 98550, 98551, 98552, 98558, 98559, 98560, 98562, 98563, 98564, 98565, 98566, 98567, 98568, 98569, 98571, 98572, 98573, 99240, 99711, 100172, 101309, 102808, 104575, 104796, 105866, 105867, 105868, 105869, 105871, 105874, 105877, 105878, 105879, 105880, 105881, 105882, 105884, 105886, 105889, 105891, 105892, 105895, 105897, 105899);
  script_xref(name:"GLSA", value:"201406-32");

  script_name(english:"GLSA-201406-32 : IcedTea JDK: Multiple vulnerabilities (BEAST)");
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
"The remote host is affected by the vulnerability described in GLSA-201406-32
(IcedTea JDK: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in the IcedTea JDK. Please
      review the CVE identifiers referenced below for details.
  
Impact :

    A remote attacker could possibly execute arbitrary code with the
      privileges of the process, cause a Denial of Service condition, obtain
      sensitive information, bypass intended security policies, or have other
      unspecified impact.
  
Workaround :

    There is no known workaround at this time."
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201406-32"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All IcedTea JDK users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-java/icedtea-bin-6.1.13.3'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:U/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Java storeImageArray() Invalid Array Indexing Vulnerability');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
  script_set_attribute(attribute:"exploit_framework_canvas", value:"true");
  script_set_attribute(attribute:"canvas_package", value:'CANVAS');
  script_cwe_id(310);

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:icedtea-bin");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2014/06/29");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/06/30");
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

if (qpkg_check(package:"dev-java/icedtea-bin", unaffected:make_list("ge 6.1.13.3", "lt 6"), vulnerable:make_list("lt 6.1.13.3"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "IcedTea JDK");
}
