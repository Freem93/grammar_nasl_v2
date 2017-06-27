#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(80618);
  script_version("$Revision: 1.2 $");
  script_cvs_date("$Date: 2016/12/27 14:30:01 $");

  script_cve_id("CVE-2011-4516", "CVE-2011-4517");

  script_name(english:"Oracle Solaris Third-Party Patch Update : ghostscript (multiple_denial_of_service_vulnerabilities7)");
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

  - Heap-based buffer overflow in the jpc_cox_getcompparms
    function in libjasper/ jpc/jpc_cs.c in JasPer 1.900.1
    allows remote attackers to execute arbitrary code or
    cause a denial of service (memory corruption) via a
    crafted numrlvls value in a coding style default (COD)
    marker segment in a JPEG2000 file. (CVE-2011-4516)

  - The jpc_crg_getparms function in libjasper/jpc/jpc_cs.c
    in JasPer 1.900.1 uses an incorrect data type during a
    certain size calculation, which allows remote attackers
    to trigger a heap-based buffer overflow and execute
    arbitrary code, or cause a denial of service (heap
    memory corruption), via a crafted component registration
    (CRG) marker segment in a JPEG2000 file. (CVE-2011-4517)"
  );
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?b5f8def1"
  );
  # https://blogs.oracle.com/sunsecurity/entry/multiple_denial_of_service_vulnerabilities7
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?99df297e"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade to Solaris 11/11 SRU 6.6.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris:11.0");
  script_set_attribute(attribute:"cpe", value:"p-cpe:/a:oracle:solaris:ghostscript");

  script_set_attribute(attribute:"patch_publication_date", value:"2012/07/10");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/01/19");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");
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

if (empty_or_null(egrep(string:pkg_list, pattern:"^ghostscript$"))) audit(AUDIT_PACKAGE_NOT_INSTALLED, "ghostscript");

flag = 0;

if (solaris_check_release(release:"0.5.11-0.175.0.6.0.6.0", sru:"SRU 6.6") > 0) flag++;

if (flag)
{
  error_extra = 'Affected package : ghostscript\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_warning(port:0, extra:error_extra);
  else security_warning(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "ghostscript");
