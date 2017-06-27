#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80612);
  script_version("$Revision: 1.1 $");
  script_cvs_date("$Date: 2015/01/19 15:17:51 $");

  script_cve_id("CVE-2012-0724", "CVE-2012-0725", "CVE-2012-0768", "CVE-2012-0769", "CVE-2012-0772", "CVE-2012-0773");

  script_name(english:"Oracle Solaris Third-Party Patch Update : flash (multiple_vulnerabilities_in_adobe_flashplayer6)");
  script_summary(english:"Check for the 'entire' version.");

  script_set_attribute(
    attribute:"synopsis", 
    value:
"The remote Solaris system is missing a security patch for third-party
software."
  );
  script_set_attribute(
    attribute:"description", 
    value:
"The remote Solaris system is missing necessary patches to address
security updates :

  - Adobe Flash Player before 11.2.202.229 in Google Chrome
    before 18.0.1025.151 allow attackers to cause a denial
    of service (memory corruption) or possibly have
    unspecified other impact via unknown vectors, a
    different vulnerability than CVE-2012-0725.
    (CVE-2012-0724)

  - Adobe Flash Player before 11.2.202.229 in Google Chrome
    before 18.0.1025.151 allow attackers to cause a denial
    of service (memory corruption) or possibly have
    unspecified other impact via unknown vectors, a
    different vulnerability than CVE-2012-0724.
    (CVE-2012-0725)

  - The Matrix3D component in Adobe Flash Player before
    10.3.183.16 and 11.x before 11.1.102.63 on Windows, Mac
    OS X, Linux, and Solaris; before 11.1.111.7 on Android
    2.x and 3.x; and before 11.1.115.7 on Android 4.x allows
    attackers to execute arbitrary code or cause a denial of
    service (memory corruption) via unspecified vectors.
    (CVE-2012-0768)

  - Adobe Flash Player before 10.3.183.16 and 11.x before
    11.1.102.63 on Windows, Mac OS X, Linux, and Solaris;
    before 11.1.111.7 on Android 2.x and 3.x; and before
    11.1.115.7 on Android 4.x does not properly handle
    integers, which allows attackers to obtain sensitive
    information via unspecified vectors. (CVE-2012-0769)

  - An unspecified ActiveX control in Adobe Flash Player
    before 10.3.183.18 and 11.x before 11.2.202.228, and AIR
    before 3.2.0.2070, on Windows does not properly perform
    URL security domain checking, which allow attackers to
    execute arbitrary code or cause a denial of service
    (memory corruption) via unknown vectors. (CVE-2012-0772)

  - The NetStream class in Adobe Flash Player before
    10.3.183.18 and 11.x before 11.2.202.228 on Windows, Mac
    OS X, and Linux; Flash Player before 10.3.183.18 and
    11.x before 11.2.202.223 on Solaris; Flash Player before
    11.1.111.8 on Android 2.x and 3.x; and AIR before
    3.2.0.2070 allows attackers to execute arbitrary code or
    cause a denial of service (memory corruption) via
    unspecified vectors. (CVE-2012-0773)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_vulnerabilities_in_adobe_flashplayer6
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?4b061741"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 7.5.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:flash");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/05/23");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015 Tenable Network Security, Inc.");
  script_family(english:"Solaris Local Security Checks");

  script_dependencies("ssh_get_info.nasl");
  script_require_keys("Host/local_checks_enabled", "Host/Solaris11/release", "Host/Solaris11/pkg-list");

  exit(0);
}


include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("solaris.inc");

if (!get_kb_item("Host/local_checks_enabled")) audit(AUDIT_LOCAL_CHECKS_NOT_ENABLED);
release = get_kb_item("Host/Solaris11/release");
if (isnull(release)) audit(AUDIT_OS_NOT, "Solaris11");
pkg_list = solaris_pkg_list_leaves();
if (isnull (pkg_list)) audit(AUDIT_PACKAGE_LIST_MISSING, "Solaris pkg-list packages");

if (empty_or_null(egrep(string:pkg_list, pattern:"^flash$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "flash");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.7.0.5.0", sru:"SRU 7.5") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : flash\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "flash");
