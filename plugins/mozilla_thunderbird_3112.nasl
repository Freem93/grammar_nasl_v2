#
# (C) Tenable Network Security, Inc.
#

include("compat.inc");

if (description)
{
  script_id(55886);
  script_version("$Revision: 1.10 $");
  script_cvs_date("$Date: 2016/05/20 14:12:06 $");

  script_cve_id(
    "CVE-2011-0084",
    "CVE-2011-2378",
    "CVE-2011-2980",
    "CVE-2011-2981",
    "CVE-2011-2982",
    "CVE-2011-2983",
    "CVE-2011-2984"
  );
  script_bugtraq_id(
    49213,
    49214,
    49216,
    49217,
    49218,
    49219,
    49223
  );
  script_osvdb_id(74581, 74582, 74583, 74584, 74585, 74586, 74587);

  script_name(english:"Mozilla Thunderbird 3.1 < 3.1.12 Multiple Vulnerabilities");
  script_summary(english:"Checks version of Thunderbird");

  script_set_attribute(attribute:"synopsis", value:
"The remote Windows host contains a mail client may be affected by
multiple vulnerabilities.");
  script_set_attribute(attribute:"description", value:
"The installed version of Thunderbird 3.1 is earlier than 3.1.12.  As
such, it is potentially affected by the following security issues :

  - Several memory safety bugs exist in the browser engine 
    that may permit remote code execution. (CVE-2011-2982)

  - A dangling pointer vulnerability exists in an SVG text
    manipulation routine. (CVE-2011-0084)

  - A dangling pointer vulnerability exists in appendChild, 
    which did not correctly account for DOM objects it 
    operated upon. (CVE-2011-2378)

  - A privilege escalation vulnerability in the event
    management code could permit JavaScript to be run in the
    wrong context. (CVE-2011-2981)

  - A privilege escalation vulnerability exists if a web page
    registered for drop events and a browser tab element was
    dropped into the content area. (CVE-2011-2984)

  - A binary planting vulnerability in
    ThinkPadSensor::Startup could permit loading a
    malicious DLL into the running process. (CVE-2011-2980)

  - A data leakage vulnerability triggered when RegExp.input
    was set could allow data from other domains to be read.
    (CVE-2011-2983)");

  script_set_attribute(attribute:"see_also", value:"http://www.mozilla.org/security/announce/2011/mfsa2011-32.html");

  script_set_attribute(attribute:"solution", value:"Upgrade to Thunderbird 3.1.12 or later.");
  script_set_cvss_base_vector("CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C");
  script_set_cvss_temporal_vector("CVSS2#E:POC/RL:OF/RC:C");
  script_set_attribute(attribute:"exploitability_ease", value:"Exploits are available");
  script_set_attribute(attribute:"exploit_available", value:"true");
  script_set_attribute(attribute:"exploithub_sku", value:"EH-11-772");
  script_set_attribute(attribute:"exploit_framework_exploithub", value:"true");
  script_set_attribute(attribute:"exploited_by_malware", value:"true");

  script_set_attribute(attribute:"vuln_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"patch_publication_date", value:"2011/08/16");
  script_set_attribute(attribute:"plugin_publication_date", value:"2011/08/17");

  script_set_attribute(attribute:"plugin_type", value:"local");
  script_set_attribute(attribute:"cpe", value:"cpe:/a:mozilla:thunderbird");
  script_end_attributes();

  script_category(ACT_GATHER_INFO);
  script_family(english:"Windows");

  script_copyright(english:"This script is Copyright (C) 2011-2016 Tenable Network Security, Inc.");
  script_dependencies("mozilla_org_installed.nasl");
  script_require_keys("Mozilla/Thunderbird/Version");
  exit(0);
}

include("mozilla_version.inc");
port = get_kb_item_or_exit("SMB/transport");

installs = get_kb_list("SMB/Mozilla/Thunderbird/*");
if (isnull(installs)) audit(AUDIT_NOT_INST, "Thunderbird");

mozilla_check_version(installs:installs, product:'thunderbird', esr:FALSE, fix:'3.1.12', min:'3.1.0', severity:SECURITY_HOLE);