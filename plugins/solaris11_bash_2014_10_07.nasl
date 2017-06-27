#
# (C) Tenable Network Security, Inc.
#
# The descriptive text and package checks in this plugin were
# extracted from the Oracle Third Party software advisories.
#
include("compat.inc");

if (description)
{
  script_id(78395);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2017/01/05 15:38:09 $");

  script_cve_id("CVE-2014-6271", "CVE-2014-6277", "CVE-2014-6278", "CVE-2014-7169", "CVE-2014-7186", "CVE-2014-7187");
  script_bugtraq_id(70103, 70137, 70152, 70154, 70165, 70166);
  script_osvdb_id(112004, 112096, 112097, 112158, 112169);

  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");

  script_name(english:"Oracle third party patch update : bash_2014_10_07");
  script_summary(english:"Check for the 'entire' version 0.5.11-0.175.2.2.0.8.0");

  script_set_attribute(attribute:"synopsis", value:
"The remote Solaris system is missing a security patch for third party
software.");
  script_set_attribute(attribute:"description", value:
"The remote Solaris system is missing necessary patches to address
critical security updates related to 'Shellshock' :

  - GNU Bash through 4.3 processes trailing strings after
    function definitions in the values of environment
    variables, which allows remote attackers to execute
    arbitrary code via a crafted environment, as
    demonstrated by vectors involving the ForceCommand
    feature in OpenSSH sshd, the 'mod_cgi' and 'mod_cgid'
    modules in the Apache HTTP Server, scripts executed by
    unspecified DHCP clients, and other situations in which
    setting the environment occurs across a privilege
    boundary from Bash execution, also known as
    'Shellshock.' Note that the original fix for this issue
    was incorrect; CVE-2014-7169 has been assigned to cover
    the vulnerability that is still present after the
    incorrect fix. (CVE-2014-6271)

  - GNU Bash through 4.3 bash43-026 does not properly parse
    function definitions in the values of environment
    variables, which allows remote attackers to execute
    arbitrary code or cause a denial of service
    (uninitialized memory access, and untrusted-pointer
    read and write operations) via a crafted environment,
    as demonstrated by vectors involving the ForceCommand
    feature in OpenSSH sshd, the 'mod_cgi' and 'mod_cgid'
    modules in the Apache HTTP Server, scripts executed by
    unspecified DHCP clients, and other situations in which
    setting the environment occurs across a privilege
    boundary from Bash execution. Note that this
    vulnerability exists because of an incomplete fix for
    CVE-2014-6271 and CVE-2014-7169. (CVE-2014-6277)

  - GNU Bash through 4.3 bash43-026 does not properly parse
    function definitions in the values of environment
    variables, which allows remote attackers to execute
    arbitrary commands via a crafted environment, as
    demonstrated by vectors involving the ForceCommand
    feature in OpenSSH sshd, the 'mod_cgi' and 'mod_cgid'
    modules in the Apache HTTP Server, scripts executed by
    unspecified DHCP clients, and other situations in which
    setting the environment occurs across a privilege
    boundary from Bash execution. Note that this
    vulnerability exists because of an incomplete fix for
    CVE-2014-6271, CVE-2014-7169, and CVE-2014-6277.
    (CVE-2014-6278)

  - GNU Bash through 4.3 bash43-025 processes trailing
    strings after certain malformed function definitions in
    the values of environment variables, which allows remote
    attackers to write to files or possibly have other
    unknown impact via a crafted environment, as
    demonstrated by vectors involving the ForceCommand
    feature in OpenSSH sshd, the 'mod_cgi' and 'mod_cgid'
    modules in the Apache HTTP Server, scripts executed by
    unspecified DHCP clients, and other situations in which
    setting the environment occurs across a privilege
    boundary from Bash execution. Note that this
    vulnerability exists because of an incomplete fix for
    CVE-2014-6271. (CVE-2014-7169)

  - The redirection implementation in 'parse.y' in GNU Bash
    through 4.3 bash43-026 allows remote attackers to cause
    a denial of service (out-of-bounds array access and
    application crash) or possibly have other unspecified
    impact via crafted use of 'here' documents, also known
    as the 'redir_stack' issue. (CVE-2014-7186)

  - An off-by-one error in the 'read_token_word' function in
    'parse.y' in GNU Bash through 4.3 bash43-026 allows
    remote attackers to cause a denial of service
    (out-of-bounds array access and application crash) or
    possibly have other unspecified impact via deeply
    nested for-loops, also known as the 'word_lineno' issue.
    (CVE-2014-7187)");
  # http://www.oracle.com/technetwork/topics/security/thirdparty-patch-map-1482893.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?b5f8def1");
  script_set_attribute(
    attribute:"see_also",
    value:"https://getupdates.oracle.com/readme/149080-02"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"http://seclists.org/oss-sec/2014/q3/650"
  );
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack/
  script_set_attribute(
    attribute:"see_also",
    value:"http://www.nessus.org/u?dacf7829"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://www.invisiblethreat.ca/2014/09/cve-2014-6271/"
  );
  script_set_attribute(
    attribute:"see_also",
    value:"https://blogs.oracle.com/patch/entry/solaris_idrs_available_on_mos"
  );
  script_set_attribute(attribute:"solution", value:"Upgrade the Solaris system to version SRU 11.2.2.8.0.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");
script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/o:oracle:solaris");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/07");
  script_set_attribute(attribute:"plugin_publication_date", value:"2014/10/13");

  script_set_attribute(attribute:"stig_severity", value:"I");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_copyright(english:"This script is Copyright (C) 2014-2017 Tenable Network Security, Inc.");
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

flag = 0;

if (preg(string:pkg_list, pattern:"(^|\n)bash(\n|$)", multiline:TRUE))
{
  if (solaris_check_release(release:"0.5.11-0.175.2.2.0.8.0", sru:"SRU 11.2.2.8.0") > 0) flag++;
}
else audit(AUDIT_PACKAGE_NOT_INSTALLED, "bash");

if (flag)
{
  error_extra = 'Affected package : bash\n' + solaris_get_report2();
  error_extra = ereg_replace(pattern:"version", replace:"OS version", string:error_extra);
  if (report_verbosity > 0) security_hole(port:0, extra:error_extra);
  else security_hole(0);
  exit(0);
}
else audit(AUDIT_PACKAGE_NOT_AFFECTED, "bash");
