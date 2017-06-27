#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82830);
  script_version("$Revision: 1.4 $");
  script_cvs_date("$Date: 2016/05/09 15:44:48 $");

  script_cve_id("CVE-2015-0204", "CVE-2015-0478", "CVE-2015-0488");
  script_bugtraq_id(71936, 74147);
  script_osvdb_id(116794, 120709, 120712);
  script_xref(name:"CERT", value:"243585");

  script_name(english:"Oracle JRockit R28.3.5 Multiple Vulnerabilities (April 2015 CPU) (FREAK)");
  script_summary(english:"Checks the version of jvm.dll.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a programming platform that is
affected by multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The remote Windows host has a version of Oracle JRockit installed that
is affected by multiple vulnerabilities :

  - A security feature bypass vulnerability, known as FREAK
    (Factoring attack on RSA-EXPORT Keys), exists due to the
    support of weak EXPORT_RSA cipher suites with keys less
    than or equal to 512 bits. A man-in-the-middle attacker
    may be able to downgrade the SSL/TLS connection to use
    EXPORT_RSA cipher suites which can be factored in a
    short amount of time, allowing the attacker to intercept
    and decrypt the traffic. (CVE-2015-0204)

  - An flaw exists in the Java Cryptography Extension (JCE)
    subcomponent due to an implementation error in the RSA
    signature. A remote attacker can exploit this flaw to
    disclose sensitive information. (CVE-2015-0478)

  - A flaw exists in the JSSE subcomponent due to improper
    parsing of X.509 certificate options. A remote attacker
    can exploit this flaw to trigger an application
    termination, resulting in a denial of service.
    (CVE-2015-0488)");
  # http://www.oracle.com/technetwork/topics/security/cpuapr2015-2365600.html
  script_set_attribute(attribute:"see_also", value:"http://www.nessus.org/u?15c09d3d");
  script_set_attribute(attribute:"see_also", value:"https://www.smacktls.com/#freak");
  script_set_attribute(attribute:"solution", value:
"Upgrade to Oracle JRockit version R28.3.6 or later as referenced in
the April 2015 Oracle Critical Patch Update advisory.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:U/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"No known exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"false");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/06");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/04/14");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/16");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:oracle:jrockit");
  script_set_attribute(attribute:"in_the_news", value:"true");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("oracle_jrockit_installed.nasl");
  script_require_keys("installed_sw/Oracle JRockit");

  exit(0);
}

include("audit.inc");
include("global_settings.inc");
include("misc_func.inc");
include("install_func.inc");

app     = "Oracle JRockit";

install = get_single_install(app_name:app, exit_if_unknown_ver:TRUE);
ver     = install['version'];
type    = install['type'];
path    = install['path'];

fix     = NULL;

if (ver =~ "^28\.3\.5($|[^0-9])")
  fix = "28.3.6";
else
  audit(AUDIT_INST_PATH_NOT_VULN, app, ver, path);

# The DLL we're looking at is a level deeper in the JDK, since it
# keeps a subset of the JRE in a subdirectory.
if (type == "JDK")  path += "\jre";

path += "\bin\jrockit\jvm.dll";

report =
  '\n  Type              : ' + type +
  '\n  Path              : ' + path +
  '\n  Installed version : ' + ver +
  '\n  Fixed version     : ' + fix +
  '\n';

port = get_kb_item("SMB/transport");
if (!port) port = 445;

if (report_verbosity > 0) security_warning(port:port, extra:report);
else security_warning(port);
