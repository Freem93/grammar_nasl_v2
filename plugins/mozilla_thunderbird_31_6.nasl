#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(82504);
  script_version("$Revision: 1.9 $");
  script_cvs_date("$Date: 2016/05/16 14:12:51 $");

  script_cve_id(
    "CVE-2015-0801",
    "CVE-2015-0802",
    "CVE-2015-0807",
    "CVE-2015-0815",
    "CVE-2015-0816"
  );
  script_bugtraq_id(
    73454,
    73455,
    73457,
    73461,
    73466
  );
  script_osvdb_id(
    119753,
    120077,
    120078,
    120079,
    120101,
    120106,
    120107
  );

  script_name(english:"Mozilla Thunderbird < 31.6 Multiple Vulnerabilities");
  script_summary(english:"Checks the version of Thunderbird.");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client that is affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The version of Thunderbird installed on the remote Windows host is
prior to 31.6. It is, therefore, affected by the following
vulnerabilities :

  - A privilege escalation vulnerability exists which
    relates to anchor navigation. A remote attacker can
    exploit this to bypass same-origin policy protections,
    allowing a possible execution of arbitrary scripts in a
    privileged context. (CVE-2015-0801)

  - Access to certain privileged internal methods is
    retained when navigating from windows created to contain
    privileged UI content to unprivileged pages. An attacker
    can exploit this to execute arbitrary JavaScript with
    elevated privileges. (CVE-2015-0802)

  - A cross-site request forgery (XSRF) vulnerability exists
    in the sendBeacon() function due to cross-origin
    resource sharing (CORS) requests following 30x
    redirections. (CVE-2015-0807)

  - Multiple memory safety issues exist within the browser
    engine. A remote attacker can exploit these to corrupt
    memory and possibly execute arbitrary code.
    (CVE-2015-0815)

  - A privilege escalation vulnerability exists related to
    documents loaded through a 'resource:' URL. An attacker
    can exploit this to load pages and execute JavaScript
    with elevated privileges. (CVE-2015-0816)");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-30/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-33/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-37/");
  script_set_attribute(attribute:"see_also", value:"https://www.mozilla.org/en-US/security/advisories/mfsa2015-40/");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 31.6 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");
  script_set_attribute(attribute:"metasploit_name", value:'Firefox PDF.js Privileged Javascript Injection');
  script_set_attribute(attribute:"exploit_framework_metasploit", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2015/01/12");
  script_set_attribute(attribute:"patch_publication_date", value:"2015/03/31");
  script_set_attribute(attribute:"plugin_publication_date", value:"2015/04/01");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2015-2016 Tenable Network Security, Inc.");

  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");

  exit(0);
}

include("mozilla_version.inc");

port = get_kb_item("SMB/transport");
if (!port) port = 445;

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'31.6', min:'31.0', severity:SECURITY_HOLE, xss:FALSE, xsrf:TRUE);
