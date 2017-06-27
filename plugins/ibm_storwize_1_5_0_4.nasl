#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(85630);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2017/04/25 20:29:05 $");

  script_cve_id(
    "CVE-2014-6271",
    "CVE-2014-7169",
    "CVE-2014-7186",
    "CVE-2014-7187",
    "CVE-2014-6277",
    "CVE-2014-6278"
  );
  script_bugtraq_id(
    70103,
    70137,
    70152,
    70165,
    70154,
    70166
  );
  script_osvdb_id(
    112004,
    112096,
    112097,
    112158,
    112169
  );
  script_xref(name:"CERT", value:"252743");
  script_xref(name:"IAVA", value:"2014-A-0142");
  script_xref(name:"EDB-ID", value:"34765");
  script_xref(name:"EDB-ID", value:"34766");
  script_xref(name:"EDB-ID", value:"34777");
  script_xref(name:"EDB-ID", value:"34860");

  script_name(english:"IBM Storwize V7000 Unified 1.3.x < 1.4.3.5 / 1.5.x < 1.5.0.4 Multiple Vulnerabilities (Shellshock)");
  script_summary(english:"Checks for vulnerable Storwize versions.");

  script_set_attribute(attribute:"synopsis", value:
"The remote IBM Storwize V7000 Unified device is affected by multiple
vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote IBM Storwize V7000 Unified device is running version 1.3.x
prior to 1.4.3.5 or 1.5.x prior to 1.5.0.4. It is, therefore, affected
by the following vulnerabilities :

  - A command injection vulnerability exists in GNU Bash
    known as Shellshock. The vulnerability is due to the
    processing of trailing strings after function
    definitions in the values of environment variables.
    This allows a remote attacker to execute arbitrary code
    via environment variable manipulation depending on the
    configuration of the system. (CVE-2014-6271)
  
  - An out-of-bounds memory access error exists in GNU Bash
    in file parse.y due to evaluating untrusted input during
    stacked redirects handling. A remote attacker can exploit
    this, via a crafted 'here' document, to execute arbitrary
    code or cause a denial of service. (CVE-2014-7186)

  - An off-by-one error exists in GNU Bash in the
    read_token_word() function in file parse.y when handling
    deeply-nested flow control constructs. A remote attacker
    can exploit this, by using deeply nested loops, to
    execute arbitrary code or cause a denial of service.
    (CVE-2014-7187)

  - A command injection vulnerability exists in GNU Bash
    known as Shellshock. The vulnerability is due to the
    processing of trailing strings after function
    definitions in the values of environment variables.
    This allows a remote attacker to execute arbitrary code
    via environment variable manipulation depending on the
    configuration of the system. (CVE-2014-6278) Note that
    this vulnerability exists because of an incomplete fix
    for CVE-2014-6271, CVE-2014-7169, and CVE-2014-6277.");
  script_set_attribute(attribute:"see_also", value:"http://www-01.ibm.com/support/docview.wss?uid=ssg1S1004898");
  script_set_attribute(attribute:"see_also", value:"http://seclists.org/oss-sec/2014/q3/650");
  # https://securityblog.redhat.com/2014/09/24/bash-specially-crafted-environment-variables-code-injection-attack
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?dacf7829");
  script_set_attribute(attribute:"see_also", value:"https://www.invisiblethreat.ca/post/shellshock/");
  script_set_attribute(attribute:"see_also", value:"http://lcamtuf.blogspot.com/2014/10/bash-bug-how-we-finally-cracked.html");
  script_set_attribute(attribute:"solution", value:
"Upgrade to IBM Storwize V7000 Unified version 1.4.3.5 / 1.5.0.4 or
later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:ND/RC:ND");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploit_framework_core", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'CUPS Filter Bash Environment Variable Code Injection (Shellshock)');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2014/09/24");
  script_set_attribute(attribute:"patch_publication_date", value:"2014/10/03");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/08/25");

  script_set_attribute(attribute:"plugin_type", value:"remote");
  script_set_attribute(attribute:"cpe", value:"cpe:/h:ibm:storwize_unified_v7000");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:ibm:storwize_v7000_unified_software");
  script_set_attribute(attribute:"stig_severity", value:"I");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Misc.");

  script_copyright(english:"This script is Copyright (C) 2015-2017 Tenable Network Security, Inc.");

  script_dependencies("ibm_storwize_detect.nbin");
  script_require_keys("Host/IBM/Storwize/version", "Host/IBM/Storwize/machine_major", "Host/IBM/Storwize/display_name");
  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");

version = get_kb_item_or_exit("Host/IBM/Storwize/version");
machine_major = get_kb_item_or_exit("Host/IBM/Storwize/machine_major");
display_name = get_kb_item_or_exit("Host/IBM/Storwize/display_name");

if (
  machine_major != "2073" # V7000 Unified
) audit(AUDIT_DEVICE_NOT_VULN, display_name);

if (version == UNKNOWN_VER || version == "Unknown")
  audit(AUDIT_UNKNOWN_APP_VER, display_name);

if (version =~ "^1\.[3-4]\.") fix = "1.4.3.5";
else if (version =~ "^1\.5\.") fix = "1.5.0.4";
else audit(AUDIT_DEVICE_NOT_VULN, display_name, version);

if (ver_compare(ver:version, fix:fix, strict:FALSE) >= 0)
  audit(AUDIT_DEVICE_NOT_VULN, display_name, version);

if (report_verbosity > 0)
{
  report =
    '\n  Name              : ' + display_name +
    '\n  Installed version : ' + version +
    '\n  Fixed version     : ' + fix +
    '\n';
  security_hole(port:0, extra:report);
}
else security_hole(port:0);
