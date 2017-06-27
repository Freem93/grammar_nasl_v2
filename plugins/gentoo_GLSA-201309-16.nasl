#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from Gentoo Linux Security Advisory GLSA 201309-16.
#
# The advisory text is Copyright (C) 2001-2016 Gentoo Foundation, Inc.
# and licensed under the Creative Commons - Attribution / Share Alike 
# license. See http://creativecommons.org/licenses/by-sa/3.0/
#

include("compat.inc");

if (description)
{
  script_id(70112);
  script_version("$Revision: 1.22 $");
  script_cvs_date("$Date: 2016/05/20 14:03:00 $");

  script_cve_id("CVE-2012-5116", "CVE-2012-5117", "CVE-2012-5118", "CVE-2012-5120", "CVE-2012-5121", "CVE-2012-5122", "CVE-2012-5123", "CVE-2012-5124", "CVE-2012-5125", "CVE-2012-5126", "CVE-2012-5127", "CVE-2012-5128", "CVE-2012-5130", "CVE-2012-5132", "CVE-2012-5133", "CVE-2012-5135", "CVE-2012-5136", "CVE-2012-5137", "CVE-2012-5138", "CVE-2012-5139", "CVE-2012-5140", "CVE-2012-5141", "CVE-2012-5142", "CVE-2012-5143", "CVE-2012-5144", "CVE-2012-5145", "CVE-2012-5146", "CVE-2012-5147", "CVE-2012-5148", "CVE-2012-5149", "CVE-2012-5150", "CVE-2012-5151", "CVE-2012-5152", "CVE-2012-5153", "CVE-2012-5154", "CVE-2013-0828", "CVE-2013-0829", "CVE-2013-0830", "CVE-2013-0831", "CVE-2013-0832", "CVE-2013-0833", "CVE-2013-0834", "CVE-2013-0835", "CVE-2013-0836", "CVE-2013-0837", "CVE-2013-0838", "CVE-2013-0839", "CVE-2013-0840", "CVE-2013-0841", "CVE-2013-0842", "CVE-2013-0879", "CVE-2013-0880", "CVE-2013-0881", "CVE-2013-0882", "CVE-2013-0883", "CVE-2013-0884", "CVE-2013-0885", "CVE-2013-0887", "CVE-2013-0888", "CVE-2013-0889", "CVE-2013-0890", "CVE-2013-0891", "CVE-2013-0892", "CVE-2013-0893", "CVE-2013-0894", "CVE-2013-0895", "CVE-2013-0896", "CVE-2013-0897", "CVE-2013-0898", "CVE-2013-0899", "CVE-2013-0900", "CVE-2013-0902", "CVE-2013-0903", "CVE-2013-0904", "CVE-2013-0905", "CVE-2013-0906", "CVE-2013-0907", "CVE-2013-0908", "CVE-2013-0909", "CVE-2013-0910", "CVE-2013-0911", "CVE-2013-0912", "CVE-2013-0916", "CVE-2013-0917", "CVE-2013-0918", "CVE-2013-0919", "CVE-2013-0920", "CVE-2013-0921", "CVE-2013-0922", "CVE-2013-0923", "CVE-2013-0924", "CVE-2013-0925", "CVE-2013-0926", "CVE-2013-2836", "CVE-2013-2837", "CVE-2013-2838", "CVE-2013-2839", "CVE-2013-2840", "CVE-2013-2841", "CVE-2013-2842", "CVE-2013-2843", "CVE-2013-2844", "CVE-2013-2845", "CVE-2013-2846", "CVE-2013-2847", "CVE-2013-2848", "CVE-2013-2849", "CVE-2013-2853", "CVE-2013-2855", "CVE-2013-2856", "CVE-2013-2857", "CVE-2013-2858", "CVE-2013-2859", "CVE-2013-2860", "CVE-2013-2861", "CVE-2013-2862", "CVE-2013-2863", "CVE-2013-2865", "CVE-2013-2867", "CVE-2013-2868", "CVE-2013-2869", "CVE-2013-2870", "CVE-2013-2871", "CVE-2013-2874", "CVE-2013-2875", "CVE-2013-2876", "CVE-2013-2877", "CVE-2013-2878", "CVE-2013-2879", "CVE-2013-2880", "CVE-2013-2881", "CVE-2013-2882", "CVE-2013-2883", "CVE-2013-2884", "CVE-2013-2885", "CVE-2013-2886", "CVE-2013-2887", "CVE-2013-2900", "CVE-2013-2901", "CVE-2013-2902", "CVE-2013-2903", "CVE-2013-2904", "CVE-2013-2905");
  script_bugtraq_id(56413, 56684, 56741, 56903, 58318, 58388, 58723, 58724, 58725, 58727, 58728, 58729, 58730, 58731, 58732, 58733, 58734, 59326, 59327, 59328, 59330, 59331, 59332, 59334, 59336, 59337, 59338, 59339, 59340, 59342, 59343, 59344, 59345, 59346, 59347, 59349, 59351, 59413, 59414, 59415, 59416, 59417, 59418, 59419, 59420, 59422, 59423, 59425, 59427, 59428, 59429, 59430, 59431, 59433, 59435, 59436, 59437, 59438, 59515, 59516, 59518, 59520, 59521, 59522, 59523, 59524, 59680, 59681, 59682, 59683, 60062, 60063, 60064, 60065, 60066, 60067, 60068, 60069, 60070, 60071, 60072, 60073, 60074, 60076, 60395, 60396, 60397, 60398, 60399, 60400, 60401, 60403, 60404, 60405, 61046, 61047, 61049, 61050, 61051, 61052, 61054, 61055, 61057, 61059, 61060, 61061, 61547, 61548, 61549, 61550, 61551, 61552, 61885, 61886, 61887, 61888, 61889, 61890, 61891);
  script_osvdb_id(87071, 87072, 87073, 87074, 87075, 87076, 87077, 87078, 87079, 87081, 87082, 87083, 87085, 87884, 87885, 87886, 87887, 87888, 88061, 88062, 88372, 88373, 88374, 88375, 88376, 88377, 89072, 89073, 89074, 89075, 89076, 89077, 89078, 89079, 89080, 89084, 89085, 89086, 89087, 89088, 89089, 89090, 89091, 89092, 89093, 89094, 89095, 89469, 89470, 89503, 89504, 90521, 90522, 90523, 90524, 90525, 90526, 90527, 90529, 90530, 90531, 90532, 90533, 90534, 90535, 90536, 90537, 90538, 90539, 90540, 90541, 90542, 90842, 90843, 90844, 90845, 90846, 90847, 90848, 90849, 90850, 90851, 90894, 90950, 91117, 91220, 91504, 91701, 91702, 91703, 91704, 91705, 91706, 91707, 91708, 91709, 91710, 91711, 91800, 91801, 91899, 92675, 92818, 93249, 93250, 93567, 93568, 93569, 93570, 93572, 93573, 93574, 93576, 93577, 93578, 93580, 93638, 93640, 93643, 93684, 93686, 93689, 93841, 93842, 93843, 93844, 93845, 93846, 93847, 93848, 93849, 93887, 93888, 93889, 93890, 93891, 93892, 93893, 93894, 93895, 93896, 93897, 93898, 93899, 93900, 93901, 93902, 93903, 93904, 93905, 93908, 93909, 93914, 93927, 93928, 93929, 93930, 93931, 93932, 93933, 93936, 93937, 93938, 93939, 93941, 93943, 93945, 93983, 93984, 93985, 93986, 93987, 93988, 93989, 93990, 93991, 93992, 93993, 93994, 93995, 93996, 93997, 93998, 93999, 94000, 94001, 94002, 94003, 94004, 94559, 94813, 94814, 94816, 95020, 95021, 95022, 95023, 95024, 95025, 95026, 95029, 95030, 95031, 95032, 95034, 95073, 95074, 95075, 95076, 95077, 95078, 95079, 95080, 95081, 95082, 95084, 95085, 95086, 95087, 95088, 95089, 95090, 95091, 95092, 95093, 95094, 95095, 95096, 95097, 95098, 95099, 95100, 95102, 95103, 95104, 95180, 95831, 95832, 95833, 95834, 95835, 95836, 95837, 95838, 95839, 96201, 96431, 96432, 96433, 96434, 96435, 96440, 96441, 96442, 96443, 96444, 96445, 96447, 96466, 96467, 96468, 96469, 96470, 96471, 96472, 101163, 101164, 101165, 101166, 101167, 101168, 103115, 103155);
  script_xref(name:"GLSA", value:"201309-16");

  script_name(english:"GLSA-201309-16 : Chromium, V8: Multiple vulnerabilities");
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
"The remote host is affected by the vulnerability described in GLSA-201309-16
(Chromium, V8: Multiple vulnerabilities)

    Multiple vulnerabilities have been discovered in Chromium and V8. Please
      review the CVE identifiers and release notes referenced below for
      details.
  
Impact :

    A context-dependent attacker could entice a user to open a specially
      crafted website or JavaScript program using Chromium or V8, possibly
      resulting in the execution of arbitrary code with the privileges of the
      process or a Denial of Service condition. Furthermore, a remote attacker
      may be able to bypass security restrictions or have other, unspecified,
      impact.
  
Workaround :

    There is no known workaround at this time."
  );
  # http://googlechromereleases.blogspot.com/2012/11/stable-channel-release-and-beta-channel.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?90289ffe"
  );
  # http://googlechromereleases.blogspot.com/2012/11/stable-channel-update.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?a0938983"
  );
  # http://googlechromereleases.blogspot.com/2012/11/stable-channel-update_29.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?47d38cbb"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://security.gentoo.org/glsa/201309-16"
  );
  script_set_attribute(
    attribute:"solution", 
    value:
"All Chromium users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose
      '>=www-client/chromium-29.0.1457.57'
    All V8 users should upgrade to the latest version:
      # emerge --sync
      # emerge --ask --oneshot --verbose '>=dev-lang/v8-3.18.5.14'"
  );
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:chromium");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:gentoo:linux:v8");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:gentoo:linux");

  script_set_attribute(attribute:"patch_publication_date", value:"2013/09/24");
  script_set_attribute(attribute:"plugin_publication_date", value:"2013/09/25");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2013-2016 Tenable Network Security, Inc.");
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

if (qpkg_check(package:"www-client/chromium", unaffected:make_list("ge 29.0.1457.57"), vulnerable:make_list("lt 29.0.1457.57"))) flag++;
if (qpkg_check(package:"dev-lang/v8", unaffected:make_list("ge 3.18.5.14"), vulnerable:make_list("lt 3.18.5.14"))) flag++;

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
  else audit(AUDIT_PACKAGE_NOT_INSTALLED, "Chromium / V8");
}
